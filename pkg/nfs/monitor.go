package nfs

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ca110us/beeward/pkg/cgroup"
	"github.com/ca110us/beeward/pkg/metrics"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-D__TARGET_ARCH_x86" -type io_stats nfs_trace ../../c/nfs_trace.bpf.c

// Monitor represents an NFS I/O monitor
type Monitor struct {
	objs           *nfs_traceObjects
	readKp         link.Link
	readKretprobe  link.Link
	writeKp        link.Link
	writeKretprobe link.Link
	cgroupMapper   *cgroup.CgroupMapper
	previousStats  map[uint32]IOStats
	nodeName       string
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
		previousStats: make(map[uint32]IOStats),
		nodeName:      nodeName,
	}

	// Attach kprobes
	if err := m.attachProbes(); err != nil {
		objs.Close()
		return nil, err
	}

	return m, nil
}

// attachProbes attaches kprobes to NFS kernel functions
func (m *Monitor) attachProbes() error {
	log.Println("Attaching eBPF programs to kernel functions...")

	// Try different NFS read function names (kernel version dependent)
	nfsFunctions := []string{
		"nfs_file_read",
		"nfs_file_read_iter",
		"nfs_file_splice_read",
	}

	var err error
	for _, fn := range nfsFunctions {
		m.readKp, err = link.Kprobe(fn, m.objs.TraceNfsReadEntry, nil)
		if err == nil {
			m.readKretprobe, err = link.Kretprobe(fn, m.objs.TraceNfsReadExit, nil)
			if err == nil {
				log.Printf("Attached to NFS read function: %s", fn)
				break
			}
		}
	}
	if m.readKp == nil {
		log.Println("WARNING: Could not attach to any NFS read function")
	}

	// Try different NFS write function names
	nfsWriteFunctions := []string{
		"nfs_file_write",
		"nfs_file_write_iter",
	}

	for _, fn := range nfsWriteFunctions {
		m.writeKp, err = link.Kprobe(fn, m.objs.TraceNfsWriteEntry, nil)
		if err == nil {
			m.writeKretprobe, err = link.Kretprobe(fn, m.objs.TraceNfsWriteExit, nil)
			if err == nil {
				log.Printf("Attached to NFS write function: %s", fn)
				break
			}
		}
	}
	if m.writeKp == nil {
		log.Println("WARNING: Could not attach to any NFS write function")
	}

	return nil
}

// Close cleans up resources
func (m *Monitor) Close() error {
	if m.readKp != nil {
		m.readKp.Close()
	}
	if m.readKretprobe != nil {
		m.readKretprobe.Close()
	}
	if m.writeKp != nil {
		m.writeKp.Close()
	}
	if m.writeKretprobe != nil {
		m.writeKretprobe.Close()
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
			if err := m.collectAndUpdateMetrics(); err != nil {
				log.Printf("Error collecting stats: %v", err)
			}
		}
	}
}

// collectAndUpdateMetrics reads BPF map and updates Prometheus metrics
func (m *Monitor) collectAndUpdateMetrics() error {
	var (
		key  uint32
		stat IOStats
	)

	currentStats := make(map[uint32]IOStats)
	newPIDs := make(map[uint32]bool) // Track new PIDs we haven't seen before
	iter := m.objs.PidIoMap.Iterate()

	entryCount := 0
	for iter.Next(&key, &stat) {
		currentStats[key] = stat
		entryCount++

		// Check if this is a new PID
		if _, seen := m.previousStats[key]; !seen {
			newPIDs[key] = true
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate BPF map: %w", err)
	}

	// For new PIDs, try to get Pod UID with automatic fallback
	for pid := range newPIDs {
		stat := currentStats[pid]
		if stat.CgroupID != 0 && !m.cgroupMapper.Exists(stat.CgroupID) {
			// Use unified function with automatic fallback
			podUID, cgroupPath := cgroup.GetPodUID(pid, stat.CgroupID)

			if podUID == "" {
				// Failed to get Pod UID even with fallback
				log.Printf("WARNING: Failed to resolve Pod UID for cgroup_id=%d pid=%d (process may have exited before detection)",
					stat.CgroupID, pid)
				continue
			}

			// Success - cache the mapping with cgroup path for cleanup
			m.cgroupMapper.Set(stat.CgroupID, podUID, cgroupPath)
			log.Printf("DEBUG: Mapped cgroup_id %d -> Pod %s (path: %s)", stat.CgroupID, podUID, cgroupPath)
		}
	}

	log.Printf("Tracking %d PIDs across %d pods", entryCount, m.cgroupMapper.Len())

	// Aggregate stats by Pod UID and update Prometheus metrics
	currentPodStats := make(map[string]PodStats)

	for pid, current := range currentStats {
		// Update previous stats for next iteration
		m.previousStats[pid] = current

		// Get Pod UID from cgroup_id mapping
		podUID := m.cgroupMapper.Get(current.CgroupID)
		if podUID == "" {
			podUID = "unknown"
		}

		// Aggregate by Pod UID
		stats, exists := currentPodStats[podUID]
		if !exists {
			stats = PodStats{
				PodUID: podUID,
				Comm:   string(bytes.TrimRight(current.Comm[:], "\x00")),
				PIDs:   []uint32{},
			}
		}
		stats.ReadBytes += current.ReadBytes
		stats.WriteBytes += current.WriteBytes
		stats.ReadCount += current.ReadCount
		stats.WriteCount += current.WriteCount
		stats.ReadIOTimeNs += current.ReadIOTimeNs
		stats.WriteIOTimeNs += current.WriteIOTimeNs

		// Track maximum latency across all PIDs in this pod
		if current.ReadLatencyMaxNs > stats.ReadLatencyMaxNs {
			stats.ReadLatencyMaxNs = current.ReadLatencyMaxNs
		}
		if current.WriteLatencyMaxNs > stats.WriteLatencyMaxNs {
			stats.WriteLatencyMaxNs = current.WriteLatencyMaxNs
		}

		stats.PIDs = append(stats.PIDs, pid)
		currentPodStats[podUID] = stats
	}

	// Update Prometheus metrics for all pods
	for podUID, stats := range currentPodStats {
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

	log.Printf("Updated metrics for %d pods (%d PIDs tracked)", len(currentPodStats), entryCount)

	// Clean up deleted cgroups first (removes entire Pods and all their PIDs)
	// This will also clean up BPF map, previousStats, metrics, and cgroup mappings
	m.cleanupDeletedCgroups()

	// Then clean up individual dead PIDs (for processes that exited but Pod still exists)
	m.cleanupDeadPIDs()

	return nil
}

// cleanupDeadPIDs removes PIDs that are no longer alive (processes have exited)
// This prevents map exhaustion from short-lived processes
func (m *Monitor) cleanupDeadPIDs() {
	var key uint32
	var stat IOStats
	iter := m.objs.PidIoMap.Iterate()

	var deadPIDs []uint32

	// Iterate through all PIDs and check if they're still alive
	for iter.Next(&key, &stat) {
		if !m.isPIDAlive(key) {
			deadPIDs = append(deadPIDs, key)
		}
	}

	// Clean up dead PIDs
	for _, pid := range deadPIDs {
		m.objs.PidIoMap.Delete(&pid)
		delete(m.previousStats, pid)
	}

	// Also clean up their start_map entries
	if len(deadPIDs) > 0 {
		m.cleanupStartMaps(deadPIDs)
		log.Printf("Cleaned up %d dead PIDs", len(deadPIDs))
	}
}

// isPIDAlive checks if a PID still exists on the system
func (m *Monitor) isPIDAlive(pid uint32) bool {
	// Check if /proc/<pid> exists
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
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

// cleanupCgroup removes all data associated with a cgroup (Pod)
func (m *Monitor) cleanupCgroup(cgroupID uint64) {
	info := m.cgroupMapper.GetInfo(cgroupID)
	if info == nil {
		return
	}

	podUID := info.PodUID

	// 1. Delete all PIDs belonging to this cgroup from BPF map and previousStats
	var key uint32
	var stat IOStats
	iter := m.objs.PidIoMap.Iterate()

	var pidsToDelete []uint32
	for iter.Next(&key, &stat) {
		if stat.CgroupID == cgroupID {
			pidsToDelete = append(pidsToDelete, key)
		}
	}

	for _, pid := range pidsToDelete {
		m.objs.PidIoMap.Delete(&pid)
		delete(m.previousStats, pid)
	}

	// Clean up start time maps (for interrupted I/O operations)
	// These maps use pid_tgid as key, so we need to iterate
	m.cleanupStartMaps(pidsToDelete)

	// 2. Delete Prometheus metrics
	metrics.NFSReadBytes.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteBytes.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSReadOps.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteOps.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSReadIOTime.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteIOTime.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSReadLatencyMax.DeleteLabelValues(podUID, m.nodeName)
	metrics.NFSWriteLatencyMax.DeleteLabelValues(podUID, m.nodeName)

	// 3. Delete cgroup mapping
	m.cgroupMapper.Delete(cgroupID)

	log.Printf("Cleaned up Pod %s (cgroup_id=%d, %d PIDs deleted)", podUID, cgroupID, len(pidsToDelete))
}

// cleanupStartMaps removes entries from read_start_map and write_start_map for deleted PIDs
// These maps track I/O start times and may have orphaned entries if processes were killed during I/O
// Normally, kretprobe will delete these entries, but we clean up here as a safeguard
func (m *Monitor) cleanupStartMaps(pidsToDelete []uint32) {
	if len(pidsToDelete) == 0 {
		return
	}

	// Create a set of PIDs to delete for fast lookup
	pidSet := make(map[uint32]bool)
	for _, pid := range pidsToDelete {
		pidSet[pid] = true
	}

	// Clean up read_start_map
	var readKey uint64
	var readVal nfs_traceIoStart
	readIter := m.objs.ReadStartMap.Iterate()
	var readKeysToDelete []uint64
	for readIter.Next(&readKey, &readVal) {
		pid := uint32(readKey >> 32) // Extract PID from pid_tgid
		if pidSet[pid] {
			readKeysToDelete = append(readKeysToDelete, readKey)
		}
	}
	for _, key := range readKeysToDelete {
		m.objs.ReadStartMap.Delete(&key)
	}

	// Clean up write_start_map
	var writeKey uint64
	var writeVal nfs_traceIoStart
	writeIter := m.objs.WriteStartMap.Iterate()
	var writeKeysToDelete []uint64
	for writeIter.Next(&writeKey, &writeVal) {
		pid := uint32(writeKey >> 32) // Extract PID from pid_tgid
		if pidSet[pid] {
			writeKeysToDelete = append(writeKeysToDelete, writeKey)
		}
	}
	for _, key := range writeKeysToDelete {
		m.objs.WriteStartMap.Delete(&key)
	}

	// Only log if we actually found orphaned entries (rare)
	if len(readKeysToDelete) > 0 || len(writeKeysToDelete) > 0 {
		log.Printf("Cleaned up %d orphaned read_start and %d write_start entries",
			len(readKeysToDelete), len(writeKeysToDelete))
	}
}
