// SPDX-License-Identifier: GPL-2.0
// NFS I/O Tracer - eBPF program to track NFS read/write operations per process

// Include vmlinux.h FIRST - contains struct pt_regs and basic types
#include "headers/vmlinux.h"

// BPF map type constants
#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0

// Now include BPF headers
// Note: __TARGET_ARCH_x86 is defined in vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 65536  // Increased from 10240 to support more PIDs

// Data structure to store I/O statistics per PID
struct io_stats {
    __u32 pid;
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

// BPF Map to store per-PID I/O statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);   // PID
    __type(value, struct io_stats);
} pid_io_map SEC(".maps");

// BPF Map to track I/O start times (for latency calculation)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);   // pid_tgid
    __type(value, struct io_start);
} read_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);   // pid_tgid
    __type(value, struct io_start);
} write_start_map SEC(".maps");

// Helper to get cgroup ID (stable across kernel versions)
static __always_inline __u64 get_cgroup_id(void)
{
    // bpf_get_current_cgroup_id() is a stable BPF helper
    // It returns a unique u64 ID that doesn't change as long as cgroup exists
    return bpf_get_current_cgroup_id();
}

// Helper to populate cgroup info
static __always_inline void read_cgroup_path(struct io_stats *stats)
{
    // Only get cgroup_id (always works on all kernels)
    stats->cgroup_id = get_cgroup_id();

    // Keep it simple: Go will handle Pod UID extraction using:
    // 1. Try /proc/<pid>/cgroup (fast, works if process still alive)
    // 2. Fallback: find /sys/fs/cgroup -inum <cgroup_id> (slower but always works)
}

// Hook into NFS file read operations
// Target: nfs_file_read_iter or vfs_read (for NFS files)
SEC("kprobe/nfs_file_read")
int trace_nfs_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Record start time for latency calculation
    struct io_start start = {
        .start_ns = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(&read_start_map, &pid_tgid, &start, BPF_ANY);

    struct io_stats *stats, new_stats = {};

    stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    if (!stats) {
        new_stats.pid = pid;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        read_cgroup_path(&new_stats);  // Just populate cgroup_id
        bpf_map_update_elem(&pid_io_map, &pid, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    }

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
    __u32 pid = pid_tgid >> 32;

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

    struct io_stats *stats, new_stats = {};

    stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    if (!stats) {
        // kretprobe executes after kprobe, but create entry if PID doesn't exist
        new_stats.pid = pid;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        read_cgroup_path(&new_stats);  // Just populate cgroup_id
        bpf_map_update_elem(&pid_io_map, &pid, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    }

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
    __u32 pid = pid_tgid >> 32;

    // Record start time for latency calculation
    struct io_start start = {
        .start_ns = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(&write_start_map, &pid_tgid, &start, BPF_ANY);

    struct io_stats *stats, new_stats = {};

    stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    if (!stats) {
        new_stats.pid = pid;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        read_cgroup_path(&new_stats);  // Just populate cgroup_id
        bpf_map_update_elem(&pid_io_map, &pid, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    }

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
    __u32 pid = pid_tgid >> 32;

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

    struct io_stats *stats, new_stats = {};

    stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    if (!stats) {
        // kretprobe executes after kprobe, but create entry if PID doesn't exist
        new_stats.pid = pid;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        read_cgroup_path(&new_stats);  // Just populate cgroup_id
        bpf_map_update_elem(&pid_io_map, &pid, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&pid_io_map, &pid);
    }

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
