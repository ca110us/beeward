package xdpratelimit

import (
	"context"
	"log"
	"time"

	"github.com/cilium/ebpf"
)

// Stats key indices matching the C defines
const (
	statsTotalPackets     = 0
	statsPassedPackets    = 1
	statsDroppedSynRate   = 2
	statsDroppedConnLimit = 3
	statsDroppedBlacklist = 4
	statsBlacklistAdds    = 5
	statsWhitelistHits    = 6
)

// statsCollector periodically reads BPF stats and updates Prometheus metrics
func (rl *RateLimiter) statsCollector(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.collectStats()
		}
	}
}

func (rl *RateLimiter) collectStats() {
	// Read per-action packet counters from PERCPU_ARRAY
	actions := map[uint32]string{
		statsPassedPackets:    "pass",
		statsDroppedSynRate:   "drop_syn_rate",
		statsDroppedConnLimit: "drop_conn_limit",
		statsDroppedBlacklist: "drop_blacklist",
	}

	for key, label := range actions {
		val, err := readPercpuSum(rl.objs.StatsMap, key)
		if err != nil {
			log.Printf("[XDP] WARNING: failed to read stats key %d: %v", key, err)
			continue
		}
		XDPPackets.WithLabelValues(label).Set(float64(val))
	}

	// Blacklist adds total
	if val, err := readPercpuSum(rl.objs.StatsMap, statsBlacklistAdds); err == nil {
		XDPBlacklistAdds.Set(float64(val))
	}

	// Whitelist hits total
	if val, err := readPercpuSum(rl.objs.StatsMap, statsWhitelistHits); err == nil {
		XDPWhitelistHits.Set(float64(val))
	}

	// Map entry counts
	XDPMapEntries.WithLabelValues("syn_rate").Set(float64(countMapEntries(rl.objs.SynRateMap)))
	XDPMapEntries.WithLabelValues("conn_count").Set(float64(countMapEntries(rl.objs.ConnCountMap)))
	XDPMapEntries.WithLabelValues("conn_track").Set(float64(countMapEntries(rl.objs.ConnTrackMap)))

	blCount := countMapEntries(rl.objs.BlacklistMap)
	XDPMapEntries.WithLabelValues("blacklist").Set(float64(blCount))
	XDPBlacklistSize.Set(float64(blCount))
}

// readPercpuSum reads a PERCPU_ARRAY entry and sums values across all CPUs
func readPercpuSum(m *ebpf.Map, key uint32) (uint64, error) {
	var values []uint64
	if err := m.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range values {
		sum += v
	}
	return sum, nil
}

// countMapEntries iterates a BPF map and counts entries
func countMapEntries(m *ebpf.Map) int {
	var (
		key     []byte
		nextKey []byte
	)

	info, err := m.Info()
	if err != nil {
		return 0
	}
	keySize := int(info.KeySize)
	key = make([]byte, keySize)
	nextKey = make([]byte, keySize)

	count := 0
	// Start with zero key
	err = m.NextKey(nil, &nextKey)
	if err != nil {
		return 0
	}
	count++
	copy(key, nextKey)

	for {
		if err := m.NextKey(&key, &nextKey); err != nil {
			break
		}
		count++
		copy(key, nextKey)
	}
	return count
}
