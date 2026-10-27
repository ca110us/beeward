package nfs

// IOStats matches the C struct from eBPF program
type IOStats struct {
	PID              uint32
	_                uint32   // Padding for alignment with C struct
	ReadBytes        uint64
	WriteBytes       uint64
	ReadCount        uint64
	WriteCount       uint64
	CgroupID         uint64   // Stable cgroup ID from bpf_get_current_cgroup_id()
	Comm             [16]byte // Process name
	ReadIOTimeNs     uint64   // Cumulative read I/O time (nanoseconds)
	WriteIOTimeNs    uint64   // Cumulative write I/O time (nanoseconds)
	ReadLatencyMaxNs uint64   // Maximum read latency (nanoseconds)
	WriteLatencyMaxNs uint64  // Maximum write latency (nanoseconds)
}

// PodStats aggregates I/O statistics by Pod UID
type PodStats struct {
	PodUID            string
	ReadBytes         uint64
	WriteBytes        uint64
	ReadCount         uint64
	WriteCount        uint64
	ReadIOTimeNs      uint64 // Cumulative read I/O time
	WriteIOTimeNs     uint64 // Cumulative write I/O time
	ReadLatencyMaxNs  uint64 // Maximum read latency
	WriteLatencyMaxNs uint64 // Maximum write latency
	PIDs              []uint32 // Track all PIDs in this pod
	Comm              string   // Representative process name
}
