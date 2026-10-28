// SPDX-License-Identifier: GPL-2.0
// XDP Rate Limiter - per-IP SYN rate limiting and connection tracking
// Protects against SYN flood and TLS Slowloris attacks at the kernel level

#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif

// --- Stats map key indices ---

#define STATS_TOTAL_PACKETS      0
#define STATS_PASSED_PACKETS     1
#define STATS_DROPPED_SYN_RATE   2
#define STATS_DROPPED_CONN_LIMIT 3
#define STATS_DROPPED_BLACKLIST  4
#define STATS_BLACKLIST_ADDS     5
#define STATS_WHITELIST_HITS     6

// --- Struct definitions for BPF maps ---

struct rate_info {
    __u64 tokens;          // Current token count
    __u64 last_refill_ns;  // Last refill timestamp (ktime_ns)
};

struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

struct config {
    __u32 syn_rate_limit;         // Max SYN packets per second per IP
    __u32 conn_limit;             // Max concurrent connections per IP
    __u64 blacklist_duration_ns;  // Blacklist duration in nanoseconds
};

// A TCP connection to a protected port, as seen on ingress (network byte order)
struct conn_key {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
};

struct conn_info {
    __u64 last_seen_ns;  // Last packet from the client (ktime_ns), for idle cleanup
};

// --- BPF Maps (8 total) ---

// 1. Per-IP SYN rate tracking (token bucket state)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);              // Source IP (network byte order)
    __type(value, struct rate_info);
    __uint(max_entries, 65536);
} syn_rate_map SEC(".maps");

// 2. Per-IP concurrent connection count
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);              // Source IP
    __type(value, __u64);            // Connection count
    __uint(max_entries, 65536);
} conn_count_map SEC(".maps");

// 3. Blacklist - banned IPs with expiry time
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);              // Source IP
    __type(value, __u64);            // Expiry time (ktime_ns)
    __uint(max_entries, 32768);
} blacklist_map SEC(".maps");

// 4. Whitelist - allowed CIDRs (LPM trie for prefix matching)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_map SEC(".maps");

// 5. Statistics counters (per-CPU for lock-free updates)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} stats_map SEC(".maps");

// 6. Runtime configuration (written by userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// 7. Protected destination ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);              // Port number
    __type(value, __u8);             // 1 = protected
    __uint(max_entries, 16);
} protected_ports_map SEC(".maps");

// 8. Open connections, so each is counted in conn_count_map exactly once:
// retransmitted SYNs aren't counted again, and only the first FIN/RST from
// either side decrements. Plain HASH, not LRU: when full, new connections go
// uncounted rather than live ones being evicted without a decrement.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
    __uint(max_entries, 131072);
} conn_track_map SEC(".maps");

// --- Helper functions ---

static __always_inline void inc_stats(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline struct config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

// Token bucket rate limiter: refill tokens based on elapsed time, consume 1
// Returns 1 if allowed, 0 if rate exceeded
static __always_inline int check_syn_rate(__u32 src_ip, __u32 rate_limit)
{
    __u64 now = bpf_ktime_get_ns();
    struct rate_info *info = bpf_map_lookup_elem(&syn_rate_map, &src_ip);

    if (!info) {
        // First SYN from this IP - create entry with (rate_limit - 1) tokens
        struct rate_info new_info = {
            .tokens = rate_limit > 0 ? rate_limit - 1 : 0,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&syn_rate_map, &src_ip, &new_info, BPF_ANY);
        return 1; // allowed
    }

    // Refill tokens based on elapsed time
    __u64 elapsed_ns = now - info->last_refill_ns;
    __u64 new_tokens = (elapsed_ns * (__u64)rate_limit) / 1000000000ULL;

    if (new_tokens > 0) {
        info->tokens += new_tokens;
        if (info->tokens > (__u64)rate_limit)
            info->tokens = (__u64)rate_limit;
        info->last_refill_ns = now;
    }

    if (info->tokens > 0) {
        info->tokens--;
        return 1; // allowed
    }

    return 0; // rate exceeded
}

// Stop tracking a closed connection and decrement its client's count. Only
// the first FIN/RST seen (from either side) still finds the entry, so each
// connection is decremented exactly once.
static __always_inline void conn_closed(struct conn_key *key)
{
    if (bpf_map_delete_elem(&conn_track_map, key) != 0)
        return;

    __u64 *conn_count = bpf_map_lookup_elem(&conn_count_map, &key->client_ip);
    if (conn_count && *conn_count > 0)
        __sync_fetch_and_add(conn_count, -1);
}

// --- Main XDP program ---

SEC("xdp")
int xdp_ratelimit(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 stats_total = STATS_TOTAL_PACKETS;
    __u32 stats_pass = STATS_PASSED_PACKETS;
    inc_stats(stats_total);

    // --- Parse Ethernet header ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto pass;

    // --- Parse IPv4 header ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass;

    // Only process TCP
    if (ip->protocol != IPPROTO_TCP)
        goto pass;

    // Validate IP header length (minimum 5 = 20 bytes)
    __u8 ihl = ip->ihl;
    if (ihl < 5)
        goto pass;

    // --- Parse TCP header ---
    // TCP header starts at IP header + (ihl * 4)
    struct tcphdr *tcp = (void *)ip + (ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        goto pass;

    // Check if destination port is protected
    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 *is_protected = bpf_map_lookup_elem(&protected_ports_map, &dport);
    if (!is_protected)
        goto pass;

    __u32 src_ip = ip->saddr; // network byte order

    // --- Whitelist check (LPM trie CIDR match) ---
    struct lpm_key wl_key = {
        .prefixlen = 32,
        .ip = src_ip,
    };
    if (bpf_map_lookup_elem(&whitelist_map, &wl_key)) {
        __u32 stats_wl = STATS_WHITELIST_HITS;
        inc_stats(stats_wl);
        goto pass;
    }

    // --- Blacklist check ---
    __u64 *bl_expiry = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (bl_expiry) {
        __u64 now = bpf_ktime_get_ns();
        if (now < *bl_expiry) {
            __u32 stats_bl = STATS_DROPPED_BLACKLIST;
            inc_stats(stats_bl);
            return XDP_DROP;
        }
        // Expired - remove from blacklist and reset connection count
        bpf_map_delete_elem(&blacklist_map, &src_ip);
        bpf_map_delete_elem(&conn_count_map, &src_ip);
        bpf_map_delete_elem(&syn_rate_map, &src_ip);
    }

    // --- Load config ---
    struct config *cfg = get_config();
    if (!cfg)
        goto pass; // No config = pass everything

    struct conn_key ck = {
        .client_ip = src_ip,
        .server_ip = ip->daddr,
        .client_port = tcp->source,
        .server_port = tcp->dest,
    };
    __u64 now = bpf_ktime_get_ns();

    // --- SYN packet handling ---
    if (tcp->syn && !tcp->ack) {
        // Check SYN rate (token bucket)
        if (!check_syn_rate(src_ip, cfg->syn_rate_limit)) {
            // Rate exceeded - add to blacklist
            __u64 expiry = bpf_ktime_get_ns() + cfg->blacklist_duration_ns;
            bpf_map_update_elem(&blacklist_map, &src_ip, &expiry, BPF_ANY);
            __u32 stats_bl_add = STATS_BLACKLIST_ADDS;
            inc_stats(stats_bl_add);
            __u32 stats_syn = STATS_DROPPED_SYN_RATE;
            inc_stats(stats_syn);
            return XDP_DROP;
        }

        // A retransmitted SYN for a connection already counted only refreshes it
        struct conn_info *ci = bpf_map_lookup_elem(&conn_track_map, &ck);
        if (ci) {
            ci->last_seen_ns = now;
            goto pass;
        }

        // Check connection count limit
        __u64 *conn_count = bpf_map_lookup_elem(&conn_count_map, &src_ip);
        if (conn_count && *conn_count >= (__u64)cfg->conn_limit) {
            // Connection limit exceeded - add to blacklist
            __u64 expiry = bpf_ktime_get_ns() + cfg->blacklist_duration_ns;
            bpf_map_update_elem(&blacklist_map, &src_ip, &expiry, BPF_ANY);
            __u32 stats_bl_add = STATS_BLACKLIST_ADDS;
            inc_stats(stats_bl_add);
            __u32 stats_conn = STATS_DROPPED_CONN_LIMIT;
            inc_stats(stats_conn);
            return XDP_DROP;
        }

        // Track and count the new connection (left uncounted if the table is full)
        struct conn_info new_ci = { .last_seen_ns = now };
        if (bpf_map_update_elem(&conn_track_map, &ck, &new_ci, BPF_NOEXIST) == 0) {
            if (conn_count) {
                __sync_fetch_and_add(conn_count, 1);
            } else {
                __u64 one = 1;
                bpf_map_update_elem(&conn_count_map, &src_ip, &one, BPF_ANY);
            }
        }
        goto pass;
    }

    // --- RST/FIN from the client: connection closed ---
    if (tcp->rst || tcp->fin) {
        conn_closed(&ck);
        goto pass;
    }

    // --- Any other packet keeps the connection's idle timer fresh ---
    struct conn_info *ci = bpf_map_lookup_elem(&conn_track_map, &ck);
    if (ci)
        ci->last_seen_ns = now;

pass:
    inc_stats(stats_pass);
    return XDP_PASS;
}

// --- TC egress program ---
// Captures outbound FIN/RST so server-initiated closes are counted down right
// away (XDP only sees inbound packets). Needs TCX (Linux 6.6+); without it,
// connections the client never FINs/RSTs are dropped by the idle cleanup.

SEC("tc")
int tc_egress_track(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0; // TC_ACT_OK

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    if (ip->protocol != IPPROTO_TCP)
        return 0;

    __u8 ihl = ip->ihl;
    if (ihl < 5)
        return 0;

    struct tcphdr *tcp = (void *)ip + (ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return 0;

    // Only care about outbound FIN/RST to protected ports
    __u16 sport = bpf_ntohs(tcp->source);
    __u8 *is_protected = bpf_map_lookup_elem(&protected_ports_map, &sport);
    if (!is_protected)
        return 0;

    if (tcp->rst || tcp->fin) {
        // Same key as on ingress: the remote client is the destination here
        struct conn_key ck = {
            .client_ip = ip->daddr,
            .server_ip = ip->saddr,
            .client_port = tcp->dest,
            .server_port = tcp->source,
        };
        conn_closed(&ck);
    }

    return 0; // TC_ACT_OK - never drop outbound packets
}

char LICENSE[] SEC("license") = "GPL";
