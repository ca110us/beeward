package nfs

// IOStats matches the C struct from eBPF program
type IOStats struct {
	PID               uint32 // Last PID seen in this cgroup (hint for /proc lookup)
	_                 uint32 // Padding for alignment with C struct
	ReadBytes         uint64
	WriteBytes        uint64
	ReadCount         uint64
	WriteCount        uint64
	CgroupID          uint64   // Stable cgroup ID from bpf_get_current_cgroup_id()
	Comm              [16]byte // Name of the first process seen in this cgroup
	ReadIOTimeNs      uint64   // Cumulative read I/O time (nanoseconds)
	WriteIOTimeNs     uint64   // Cumulative write I/O time (nanoseconds)
	ReadLatencyMaxNs  uint64   // Maximum read latency (nanoseconds)
	WriteLatencyMaxNs uint64   // Maximum write latency (nanoseconds)
}

// PodStats holds monotonic I/O totals for a Pod, accumulated from the
// per-cgroup BPF counters so they survive containers restarting and
// BPF entries being evicted.
type PodStats struct {
	ReadBytes         uint64
	WriteBytes        uint64
	ReadCount         uint64
	WriteCount        uint64
	ReadIOTimeNs      uint64 // Cumulative read I/O time
	WriteIOTimeNs     uint64 // Cumulative write I/O time
	ReadLatencyMaxNs  uint64 // Maximum read latency
	WriteLatencyMaxNs uint64 // Maximum write latency
}

// addDelta adds the growth of a cgroup's counters between two snapshots.
// A zero prev (first time this entry is seen) counts the full value.
func (p *PodStats) addDelta(prev, cur IOStats) {
	p.ReadBytes += delta(prev.ReadBytes, cur.ReadBytes)
	p.WriteBytes += delta(prev.WriteBytes, cur.WriteBytes)
	p.ReadCount += delta(prev.ReadCount, cur.ReadCount)
	p.WriteCount += delta(prev.WriteCount, cur.WriteCount)
	p.ReadIOTimeNs += delta(prev.ReadIOTimeNs, cur.ReadIOTimeNs)
	p.WriteIOTimeNs += delta(prev.WriteIOTimeNs, cur.WriteIOTimeNs)

	if cur.ReadLatencyMaxNs > p.ReadLatencyMaxNs {
		p.ReadLatencyMaxNs = cur.ReadLatencyMaxNs
	}
	if cur.WriteLatencyMaxNs > p.WriteLatencyMaxNs {
		p.WriteLatencyMaxNs = cur.WriteLatencyMaxNs
	}
}

func delta(prev, cur uint64) uint64 {
	if cur < prev {
		// The BPF entry was deleted and recreated, so counting restarted from zero
		return cur
	}
	return cur - prev
}
