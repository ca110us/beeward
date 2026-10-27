// SPDX-License-Identifier: GPL-2.0
// NFS I/O Tracer - eBPF program to track NFS read/write operations per cgroup

// Include vmlinux.h FIRST - contains struct pt_regs and basic types
#include "headers/vmlinux.h"

// BPF map type constants
#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0
#define BPF_NOEXIST 1

// Now include BPF headers
// Note: __TARGET_ARCH_x86 is defined in vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_CGROUPS 10240   // One entry per container cgroup doing NFS I/O
#define MAX_INFLIGHT 65536  // One entry per thread with an NFS call in flight

// Data structure to store I/O statistics per cgroup.
// Keying by cgroup (not PID) keeps counters monotonic when processes exit
// and avoids misattribution when a PID is reused by another Pod.
struct io_stats {
    __u32 pid;   // Last PID seen in this cgroup, used by userspace to resolve the Pod via /proc
    __u32 _pad;  // Explicit padding for 8-byte alignment
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_count;
    __u64 write_count;
    __u64 cgroup_id;  // Stable cgroup ID from bpf_get_current_cgroup_id()
    char comm[TASK_COMM_LEN];
    // Latency tracking (similar to node_disk_io_time_seconds_total)
    __u64 read_io_time_ns;      // Cumulative read I/O time (nanoseconds)
    __u64 write_io_time_ns;     // Cumulative write I/O time (nanoseconds)
    __u64 read_latency_max_ns;  // Maximum read latency (nanoseconds)
    __u64 write_latency_max_ns; // Maximum write latency (nanoseconds)
};

// Structure to track I/O start time
struct io_start {
    __u64 start_ns;  // Start timestamp in nanoseconds
};

// BPF Map to store per-cgroup I/O statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CGROUPS);
    __type(key, __u64);   // cgroup_id
    __type(value, struct io_stats);
} cgroup_io_map SEC(".maps");

// BPF Map to track I/O start times (for latency calculation).
// Keyed per thread so concurrent calls in the same cgroup don't overwrite each other.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_INFLIGHT);
    __type(key, __u64);   // pid_tgid
    __type(value, struct io_start);
} read_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_INFLIGHT);
    __type(key, __u64);   // pid_tgid
    __type(value, struct io_start);
} write_start_map SEC(".maps");

// Look up (or create) the stats entry for the current task's cgroup
static __always_inline struct io_stats *get_stats(__u64 pid_tgid)
{
    // bpf_get_current_cgroup_id() is a stable BPF helper: a unique ID
    // that doesn't change as long as the cgroup exists
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct io_stats *stats = bpf_map_lookup_elem(&cgroup_io_map, &cgroup_id);
    if (!stats) {
        struct io_stats new_stats = {};
        new_stats.cgroup_id = cgroup_id;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        // NOEXIST: another CPU may have created the entry concurrently
        bpf_map_update_elem(&cgroup_io_map, &cgroup_id, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&cgroup_io_map, &cgroup_id);
        if (!stats)
            return 0;
    }

    // Go resolves the Pod via /proc/<pid>/cgroup, falling back to an inode
    // search of /sys/fs/cgroup by cgroup_id if this PID has already exited
    stats->pid = pid_tgid >> 32;
    return stats;
}

// Hook into NFS file read operations
// Target: nfs_file_read_iter or vfs_read (for NFS files)
SEC("kprobe/nfs_file_read")
int trace_nfs_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Record start time for latency calculation
    struct io_start start = {
        .start_ns = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(&read_start_map, &pid_tgid, &start, BPF_ANY);

    struct io_stats *stats = get_stats(pid_tgid);
    if (stats) {
        __sync_fetch_and_add(&stats->read_count, 1);
    }

    return 0;
}

// Hook into NFS file read return to get actual bytes read
SEC("kretprobe/nfs_file_read")
int BPF_KRETPROBE(trace_nfs_read_exit, long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Calculate latency
    struct io_start *start = bpf_map_lookup_elem(&read_start_map, &pid_tgid);
    __u64 duration_ns = 0;
    if (start) {
        duration_ns = bpf_ktime_get_ns() - start->start_ns;
        bpf_map_delete_elem(&read_start_map, &pid_tgid);
    }

    // ret is the function return value (bytes read)
    // Note: NFS functions return ssize_t, positive values indicate successful read bytes
    if (ret <= 0) {
        return 0;
    }

    struct io_stats *stats = get_stats(pid_tgid);
    if (stats) {
        __sync_fetch_and_add(&stats->read_bytes, (__u64)ret);

        // Accumulate I/O time (similar to node_disk_io_time_seconds_total)
        if (duration_ns > 0) {
            __sync_fetch_and_add(&stats->read_io_time_ns, duration_ns);

            // Update max latency (non-atomic, acceptable for monitoring)
            if (duration_ns > stats->read_latency_max_ns) {
                stats->read_latency_max_ns = duration_ns;
            }
        }
    }

    return 0;
}

// Hook into NFS file write operations
SEC("kprobe/nfs_file_write")
int trace_nfs_write_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Record start time for latency calculation
    struct io_start start = {
        .start_ns = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(&write_start_map, &pid_tgid, &start, BPF_ANY);

    struct io_stats *stats = get_stats(pid_tgid);
    if (stats) {
        __sync_fetch_and_add(&stats->write_count, 1);
    }

    return 0;
}

// Hook into NFS file write return to get actual bytes written
SEC("kretprobe/nfs_file_write")
int BPF_KRETPROBE(trace_nfs_write_exit, long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Calculate latency
    struct io_start *start = bpf_map_lookup_elem(&write_start_map, &pid_tgid);
    __u64 duration_ns = 0;
    if (start) {
        duration_ns = bpf_ktime_get_ns() - start->start_ns;
        bpf_map_delete_elem(&write_start_map, &pid_tgid);
    }

    // ret is the function return value (bytes written)
    if (ret <= 0) {
        return 0;
    }

    struct io_stats *stats = get_stats(pid_tgid);
    if (stats) {
        __sync_fetch_and_add(&stats->write_bytes, (__u64)ret);

        // Accumulate I/O time (similar to node_disk_io_time_seconds_total)
        if (duration_ns > 0) {
            __sync_fetch_and_add(&stats->write_io_time_ns, duration_ns);

            // Update max latency (non-atomic, acceptable for monitoring)
            if (duration_ns > stats->write_latency_max_ns) {
                stats->write_latency_max_ns = duration_ns;
            }
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
