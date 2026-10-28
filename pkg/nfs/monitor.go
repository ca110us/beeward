package nfs

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/ca110us/beeward/pkg/cgroup"
	"github.com/ca110us/beeward/pkg/metrics"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-D__TARGET_ARCH_x86" -type io_stats nfs_trace ../../c/nfs_trace.bpf.c

const (
	// idleCgroupTimeout is how long a cgroup can go without NFS I/O before its
	// BPF entry is evicted. Its contribution stays in the Pod totals, so this
	// only bounds map usage (e.g. host cgroups that never resolve to a Pod).
	idleCgroupTimeout = time.Hour

	// staleStartAge is how old an I/O start entry must be before it is treated
	// as orphaned (thread killed mid-call, so the kretprobe never ran).
	// Kept long so genuinely hung NFS calls still report their latency.
	staleStartAge = time.Hour
)

// Monitor represents an NFS I/O monitor
type Monitor struct {
	objs          *nfs_traceObjects
	links         []link.Link // kprobe/kretprobe links, empty until the nfs module is loaded
	cgroupMapper  *cgroup.CgroupMapper
	previousStats map[uint64]IOStats   // Last BPF snapshot per cgroup, for computing deltas
	lastActive    map[uint64]time.Time // When each cgroup's counters last changed
	podTotals     map[string]*PodStats // Monotonic totals per Pod UID
	nodeName      string
}

// NewMonitor creates a new NFS monitor
func NewMonitor(nodeName string) (*Monitor, error) {
	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("WARNING: Failed to remove memlock limit: %v", err)
		log.Printf("Attempting to continue with existing limits...")
	}

	// Load eBPF program
	spec, err := loadNfs_trace()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	objs := &nfs_traceObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	m := &Monitor{
		objs:          objs,
		cgroupMapper:  cgroup.NewCgroupMapper(),
		previousStats: make(map[uint64]IOStats),
		lastActive:    make(map[uint64]time.Time),
		podTotals:     make(map[string]*PodStats),
		nodeName:      nodeName,
	}

	log.Println("Attaching eBPF programs to kernel functions...")
	m.attachProbes(true)

	return m, nil
}

// NFS kernel functions to trace. All that exist are attached: read(2) goes
// through nfs_file_read, while on newer kernels sendfile/splice reads go
// through nfs_file_splice_read instead (older kernels route them via
// nfs_file_read, where nfs_file_splice_read doesn't exist).
var (
	nfsReadFunctions  = []string{"nfs_file_read", "nfs_file_splice_read"}
	nfsWriteFunctions = []string{"nfs_file_write"}
)

// probesAttached reports whether the NFS probes are attached
func (m *Monitor) probesAttached() bool {
	return len(m.links) > 0
}

// attachProbes attaches the NFS kprobes. It is retried on every collection
// until it succeeds, because the nfs module is usually loaded only when the
// first NFS volume is mounted, which can be after Beeward starts.
func (m *Monitor) attachProbes(warnMissing bool) {
	for _, fn := range nfsReadFunctions {
		m.attachKprobe(fn, "read", m.objs.TraceNfsReadEntry, m.objs.TraceNfsReadExit)
	}
	for _, fn := range nfsWriteFunctions {
		m.attachKprobe(fn, "write", m.objs.TraceNfsWriteEntry, m.objs.TraceNfsWriteExit)
	}

	if !m.probesAttached() && warnMissing {
		log.Println("WARNING: Could not attach to any NFS function (nfs module not loaded yet?), will retry")
	}
}

// attachKprobe attaches entry/exit programs to fn, skipping it if fn
// doesn't exist on this kernel
func (m *Monitor) attachKprobe(fn, kind string, entry, exit *ebpf.Program) {
	kp, err := link.Kprobe(fn, entry, nil)
	if err != nil {
		return
	}
	krp, err := link.Kretprobe(fn, exit, nil)
	if err != nil {
		kp.Close()
		return
	}
	m.links = append(m.links, kp, krp)
	log.Printf("Attached to NFS %s function: %s", kind, fn)
}

// Close cleans up resources
func (m *Monitor) Close() error {
	for _, l := range m.links {
		l.Close()
	}
	if m.objs != nil {
		return m.objs.Close()
	}
	return nil
}

// Run starts the monitoring loop
func (m *Monitor) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Monitoring NFS I/O every %v...", interval)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if !m.probesAttached() {
				m.attachProbes(false)
			}
			if err := m.collectAndUpdateMetrics(); err != nil {
				log.Printf("Error collecting stats: %v", err)
			}
		}
	}
}

// collectAndUpdateMetrics reads BPF map and updates Prometheus metrics
func (m *Monitor) collectAndUpdateMetrics() error {
	var (
		key  uint64
		stat IOStats
	)

	now := time.Now()
	entryCount := 0
	iter := m.objs.CgroupIoMap.Iterate()

	for iter.Next(&key, &stat) {
		entryCount++

		prev, seen := m.previousStats[key]
		if !seen {
			m.resolveCgroup(key, stat.PID)
		} else if prev == stat {
			continue // No I/O since last collection
		}

		// Get Pod UID from cgroup_id mapping
		podUID := m.cgroupMapper.Get(key)
		if podUID == "" {
			podUID = "unknown"
		}

		totals := m.podTotals[podUID]
		if totals == nil {
			totals = &PodStats{}
			m.podTotals[podUID] = totals
		}
		totals.addDelta(prev, stat)

		m.previousStats[key] = stat
		m.lastActive[key] = now
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate BPF map: %w", err)
	}

	// Update Prometheus metrics for all pods
	for podUID, stats := range m.podTotals {
		metrics.NFSReadBytes.WithLabelValues(podUID, m.nodeName).Set(float64(stats.ReadBytes))
		metrics.NFSWriteBytes.WithLabelValues(podUID, m.nodeName).Set(float64(stats.WriteBytes))
		metrics.NFSReadOps.WithLabelValues(podUID, m.nodeName).Set(float64(stats.ReadCount))
		metrics.NFSWriteOps.WithLabelValues(podUID, m.nodeName).Set(float64(stats.WriteCount))

		// Convert nanoseconds to seconds for Prometheus metrics
		metrics.NFSReadIOTime.WithLabelValues(podUID, m.nodeName).Set(float64(stats.ReadIOTimeNs) / 1e9)
		metrics.NFSWriteIOTime.WithLabelValues(podUID, m.nodeName).Set(float64(stats.WriteIOTimeNs) / 1e9)
		metrics.NFSReadLatencyMax.WithLabelValues(podUID, m.nodeName).Set(float64(stats.ReadLatencyMaxNs) / 1e9)
		metrics.NFSWriteLatencyMax.WithLabelValues(podUID, m.nodeName).Set(float64(stats.WriteLatencyMaxNs) / 1e9)
	}

	log.Printf("Updated metrics for %d pods (%d cgroups tracked)", len(m.podTotals), entryCount)

	// Clean up deleted Pods (removes their cgroups, totals and metrics)
	m.cleanupDeletedCgroups()

	// Bound map usage: drop cgroups with no recent I/O and orphaned start entries
	m.evictIdleCgroups(now)
	m.cleanupStaleStartMaps()

	return nil
}

// resolveCgroup maps a newly seen cgroup to its Pod UID, using the last PID
// seen in it for the fast /proc lookup
func (m *Monitor) resolveCgroup(cgroupID uint64, pid uint32) {
	if cgroupID == 0 || m.cgroupMapper.Exists(cgroupID) {
		return
	}

	// Use unified function with automatic fallback
	podUID, cgroupPath := cgroup.GetPodUID(pid, cgroupID)
	if podUID == "" {
		// Failed to get Pod UID even with fallback
		log.Printf("WARNING: Failed to resolve Pod UID for cgroup_id=%d pid=%d (not a Pod, or process exited before detection)",
			cgroupID, pid)
		return
	}

	// Success - cache the mapping with cgroup path for cleanup
	m.cgroupMapper.Set(cgroupID, podUID, cgroupPath)
	log.Printf("DEBUG: Mapped cgroup_id %d -> Pod %s (path: %s)", cgroupID, podUID, cgroupPath)
}

// cleanupDeletedCgroups removes cgroups (Pods) that no longer exist
func (m *Monitor) cleanupDeletedCgroups() {
	var toDelete []uint64

	// Check each tracked cgroup to see if it still exists
	for _, cgroupID := range m.cgroupMapper.GetAllCgroupIDs() {
		info := m.cgroupMapper.GetInfo(cgroupID)
		if info == nil {
			continue
		}

		// Check if cgroup directory still exists
		if _, err := os.Stat(info.CgroupPath); os.IsNotExist(err) {
			toDelete = append(toDelete, cgroupID)
		}
	}

	// Clean up each deleted cgroup
	for _, cgroupID := range toDelete {
		m.cleanupCgroup(cgroupID)
	}

	if len(toDelete) > 0 {
		log.Printf("Cleaned up %d deleted cgroups", len(toDelete))
	}
}

// cleanupCgroup removes all data associated with a cgroup, and the Pod's
// totals and metrics once none of its cgroups are tracked anymore
func (m *Monitor) cleanupCgroup(cgroupID uint64) {
	info := m.cgroupMapper.GetInfo(cgroupID)
	if info == nil {
		return
	}

	podUID := info.PodUID

	// 1. Delete the cgroup from BPF map and Go-side state
	m.objs.CgroupIoMap.Delete(&cgroupID)
	delete(m.previousStats, cgroupID)
	delete(m.lastActive, cgroupID)
	m.cgroupMapper.Delete(cgroupID)

	if m.cgroupMapper.HasPod(podUID) {
		return
	}

	// 2. Delete Pod totals and Prometheus metrics
	delete(m.podTotals, podUID)
	metrics.NFSReadBytes.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteBytes.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSReadOps.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteOps.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSReadIOTime.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteIOTime.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSReadLatencyMax.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteLatencyMax.DeleteLabelValues(podUID, m.nodeName)

	log.Printf("Cleaned up Pod %s (cgroup_id=%d)", podUID, cgroupID)
}

// evictIdleCgroups drops BPF entries for cgroups with no I/O for
// idleCgroupTimeout. Pod totals and cgroup mappings are kept, so if the
// cgroup becomes active again its fresh counters are simply added on top.
func (m *Monitor) evictIdleCgroups(now time.Time) {
	evicted := 0
	for cgroupID, last := range m.lastActive {
		if now.Sub(last) < idleCgroupTimeout {
			continue
		}
		m.objs.CgroupIoMap.Delete(&cgroupID)
		delete(m.previousStats, cgroupID)
		delete(m.lastActive, cgroupID)
		evicted++
	}

	if evicted > 0 {
		log.Printf("Evicted %d idle cgroups", evicted)
	}
}

// cleanupStaleStartMaps removes orphaned entries from read_start_map and write_start_map.
// Normally the kretprobe deletes them, but a thread killed during I/O leaves one behind.
func (m *Monitor) cleanupStaleStartMaps() {
	// bpf_ktime_get_ns() uses CLOCK_MONOTONIC
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return
	}
	now := uint64(ts.Nano())
	if now < uint64(staleStartAge) {
		return
	}
	cutoff := now - uint64(staleStartAge)

	removed := 0
	for _, startMap := range []*ebpf.Map{m.objs.ReadStartMap, m.objs.WriteStartMap} {
		var (
			key  uint64
			val  nfs_traceIoStart
			keys []uint64
		)
		iter := startMap.Iterate()
		for iter.Next(&key, &val) {
			if val.StartNs < cutoff {
				keys = append(keys, key)
			}
		}
		for _, k := range keys {
			startMap.Delete(&k)
		}
		removed += len(keys)
	}

	// Only log if we actually found orphaned entries (rare)
	if removed > 0 {
		log.Printf("Cleaned up %d orphaned I/O start entries", removed)
	}
}
