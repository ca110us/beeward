package xdpratelimit

import (
	"context"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// blacklistCleaner periodically removes expired blacklist entries
func (rl *RateLimiter) blacklistCleaner(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.cleanBlacklist()
		}
	}
}

// monotonicNowNs returns the current time on the same clock as bpf_ktime_get_ns
func monotonicNowNs() (uint64, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Printf("[XDP] WARNING: ClockGettime failed: %v", err)
		return 0, false
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec), true
}

func (rl *RateLimiter) cleanBlacklist() {
	nowNs, ok := monotonicNowNs()
	if !ok {
		return
	}

	var key uint32
	var expiry uint64
	var toDelete []uint32

	iter := rl.objs.BlacklistMap.Iterate()
	for iter.Next(&key, &expiry) {
		if expiry <= nowNs {
			toDelete = append(toDelete, key)
		}
	}

	for _, k := range toDelete {
		// Delete conn_count and syn_rate BEFORE blacklist so that if a packet
		// arrives mid-cleanup, BPF still sees the blacklist entry and DROPs,
		// avoiding the race where stale conn_count causes immediate re-blacklisting.
		rl.objs.ConnCountMap.Delete(&k)
		rl.objs.SynRateMap.Delete(&k)
		rl.objs.BlacklistMap.Delete(&k)
	}
	if len(toDelete) > 0 {
		log.Printf("[XDP] Cleaned %d expired blacklist entries (with conn/rate reset)", len(toDelete))
	}
}

// connCountCleaner periodically drops idle tracked connections and removes
// zero-count entries from conn_count_map. Counting itself happens in kernel:
// XDP on SYN and client FIN/RST, TC egress on server FIN/RST.
func (rl *RateLimiter) connCountCleaner(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.cleanConnTrack()
			rl.cleanConnCount()
		}
	}
}

// cleanConnTrack stops counting connections with no client packets for
// ConnIdleTimeout: ones that ended without a FIN/RST we could see (client
// vanished, or closed by the server on kernels without TC egress).
func (rl *RateLimiter) cleanConnTrack() {
	nowNs, ok := monotonicNowNs()
	if !ok {
		return
	}
	idleNs := uint64(rl.cfg.ConnIdleTimeout) * 1_000_000_000

	var (
		key   xdp_ratelimitConnKey
		info  xdp_ratelimitConnInfo
		stale []xdp_ratelimitConnKey
	)
	iter := rl.objs.ConnTrackMap.Iterate()
	for iter.Next(&key, &info) {
		if nowNs > info.LastSeenNs && nowNs-info.LastSeenNs > idleNs {
			stale = append(stale, key)
		}
	}

	removed := 0
	for _, k := range stale {
		// Only decrement if we removed it, not a FIN/RST that raced us in BPF
		if err := rl.objs.ConnTrackMap.Delete(&k); err != nil {
			continue
		}
		removed++
		// Not atomic with BPF increments; a race can only undercount (fail open)
		var count uint64
		if rl.objs.ConnCountMap.Lookup(&k.ClientIp, &count) == nil && count > 0 {
			rl.objs.ConnCountMap.Update(&k.ClientIp, count-1, ebpf.UpdateExist)
		}
	}
	if removed > 0 {
		log.Printf("[XDP] Stopped counting %d idle connections", removed)
	}
}

func (rl *RateLimiter) cleanConnCount() {
	var key uint32
	var count uint64
	var toDelete []uint32

	iter := rl.objs.ConnCountMap.Iterate()
	for iter.Next(&key, &count) {
		if count == 0 {
			toDelete = append(toDelete, key)
		}
	}

	for _, k := range toDelete {
		rl.objs.ConnCountMap.Delete(&k)
	}
	if len(toDelete) > 0 {
		log.Printf("[XDP] Cleaned %d zero-count connection entries", len(toDelete))
	}
}
