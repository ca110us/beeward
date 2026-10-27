package xdpratelimit

import "github.com/prometheus/client_golang/prometheus"

var (
	// Packet-level statistics (from BPF stats_map, PERCPU aggregated)
	XDPPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xdp_ratelimit_packets",
			Help: "Cumulative packets processed by XDP rate limiter by action (from BPF PERCPU counters)",
		},
		[]string{"action"},
	)

	// Blacklist state
	XDPBlacklistSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "xdp_ratelimit_blacklist_size",
			Help: "Current number of IPs in the blacklist",
		},
	)
	XDPBlacklistAdds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "xdp_ratelimit_blacklist_adds",
			Help: "Cumulative number of IPs added to blacklist (from BPF counter)",
		},
	)

	// Whitelist
	XDPWhitelistHits = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "xdp_ratelimit_whitelist_hits",
			Help: "Cumulative whitelist hit count (from BPF counter)",
		},
	)
	XDPWhitelistSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "xdp_ratelimit_whitelist_size",
			Help: "Number of whitelist CIDR entries",
		},
	)

	// BPF map usage
	XDPMapEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xdp_ratelimit_map_entries",
			Help: "Current entries in BPF maps",
		},
		[]string{"map"},
	)

	// Configuration
	XDPConfigGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xdp_ratelimit_config",
			Help: "Current configuration parameter values",
		},
		[]string{"param"},
	)
)

func init() {
	prometheus.MustRegister(XDPPackets)
	prometheus.MustRegister(XDPBlacklistSize)
	prometheus.MustRegister(XDPBlacklistAdds)
	prometheus.MustRegister(XDPWhitelistHits)
	prometheus.MustRegister(XDPWhitelistSize)
	prometheus.MustRegister(XDPMapEntries)
	prometheus.MustRegister(XDPConfigGauge)
}
