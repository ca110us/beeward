package xdpratelimit

import (
	"context"
	"log"
	"time"

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

func (rl *RateLimiter) cleanBlacklist() {
	// Get current monotonic time (same clock as bpf_ktime_get_ns)
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Printf("[XDP] WARNING: ClockGettime failed: %v", err)
		return
	}
	nowNs := uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)

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

// connCountCleaner periodically removes zero-count entries from conn_count_map.
// Actual count maintenance is handled in kernel by XDP (ingress) + TC (egress).
func (rl *RateLimiter) connCountCleaner(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.cleanConnCount()
		}
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
