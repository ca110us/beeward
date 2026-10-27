package xdpratelimit

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-D__TARGET_ARCH_x86" -type config -type rate_info -type lpm_key xdp_ratelimit ../../c/xdp_ratelimit.bpf.c

// RateLimiter manages the XDP rate limiting program
type RateLimiter struct {
	objs    *xdp_ratelimitObjects
	xdpLink link.Link
	tcLink  link.Link
	cfg     *Config
}

// Run starts the XDP rate limiter module. It blocks until ctx is canceled.
func Run(ctx context.Context) error {
	cfg := LoadConfig()
	log.Printf("[XDP] Starting rate limiter (syn_rate=%d/s, conn_limit=%d, blacklist=%ds)",
		cfg.SynRateLimit, cfg.ConnLimit, cfg.BlacklistDuration)

	// Remove memlock limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[XDP] WARNING: Failed to remove memlock limit: %v", err)
	}

	// Load BPF program
	spec, err := loadXdp_ratelimit()
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	objs := &xdp_ratelimitObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer objs.Close()

	rl := &RateLimiter{
		objs: objs,
		cfg:  cfg,
	}

	// Detect main network interface
	ifaceName, ifaceIndex, err := DetectMainInterface()
	if err != nil {
		return fmt.Errorf("detect main interface: %w", err)
	}
	log.Printf("[XDP] Detected main interface: %s (index %d)", ifaceName, ifaceIndex)

	// Attach XDP program (ingress) - try native mode first, fall back to generic
	rl.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRatelimit,
		Interface: ifaceIndex,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("[XDP] Native XDP attach failed (%v), trying generic mode", err)
		rl.xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpRatelimit,
			Interface: ifaceIndex,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attach XDP (both native and generic failed): %w", err)
		}
		log.Printf("[XDP] Attached XDP in generic (SKB) mode on %s", ifaceName)
	} else {
		log.Printf("[XDP] Attached XDP in native (driver) mode on %s", ifaceName)
	}
	defer rl.xdpLink.Close()

	// Attach TC egress program to track outbound FIN/RST for accurate conn_count
	rl.tcLink, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgressTrack,
		Attach:    ebpf.AttachTCXEgress,
		Interface: ifaceIndex,
	})
	if err != nil {
		log.Printf("[XDP] WARNING: TC egress attach failed: %v (conn_count may drift)", err)
	} else {
		log.Printf("[XDP] Attached TC egress on %s for conn_count tracking", ifaceName)
	}
	if rl.tcLink != nil {
		defer rl.tcLink.Close()
	}

	// Pin maps for bpftool inspection and persistence
	if err := rl.pinMaps(); err != nil {
		log.Printf("[XDP] WARNING: Failed to pin maps: %v (continuing without pinning)", err)
	}

	// Write initial configuration to BPF maps
	if err := rl.writeConfig(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// Write whitelist CIDRs
	if err := WriteWhitelist(objs.WhitelistMap, cfg.WhitelistCIDRs); err != nil {
		log.Printf("[XDP] WARNING: Failed to write whitelist: %v", err)
	}

	// Write protected ports
	if err := rl.writeProtectedPorts(); err != nil {
		return fmt.Errorf("write protected ports: %w", err)
	}

	// Publish config as metrics
	XDPConfigGauge.WithLabelValues("syn_rate_limit").Set(float64(cfg.SynRateLimit))
	XDPConfigGauge.WithLabelValues("conn_limit").Set(float64(cfg.ConnLimit))

	log.Printf("[XDP] Rate limiter active on %s", ifaceName)

	// Start background goroutines
	go rl.statsCollector(ctx)
	go rl.connCountCleaner(ctx)
	go rl.blacklistCleaner(ctx)

	// Block until context canceled
	<-ctx.Done()
	log.Printf("[XDP] Shutting down rate limiter")
	return nil
}

// pinMaps pins BPF maps to /sys/fs/bpf for bpftool inspection
func (rl *RateLimiter) pinMaps() error {
	if err := os.MkdirAll(rl.cfg.PinPath, 0700); err != nil {
		return fmt.Errorf("create pin dir %s: %w", rl.cfg.PinPath, err)
	}

	maps := map[string]*ebpf.Map{
		"syn_rate_map":        rl.objs.SynRateMap,
		"conn_count_map":      rl.objs.ConnCountMap,
		"blacklist_map":       rl.objs.BlacklistMap,
		"whitelist_map":       rl.objs.WhitelistMap,
		"stats_map":           rl.objs.StatsMap,
		"config_map":          rl.objs.ConfigMap,
		"protected_ports_map": rl.objs.ProtectedPortsMap,
	}

	for name, m := range maps {
		path := filepath.Join(rl.cfg.PinPath, name)
		// Remove stale pin file from previous run so we always pin the current map
		os.Remove(path)
		if err := m.Pin(path); err != nil {
			log.Printf("[XDP] WARNING: Failed to pin %s: %v", name, err)
		}
	}
	return nil
}

// writeConfig writes rate limiter parameters to the BPF config_map
func (rl *RateLimiter) writeConfig() error {
	key := uint32(0)
	cfg := xdp_ratelimitConfig{
		SynRateLimit:        uint32(rl.cfg.SynRateLimit),
		ConnLimit:           uint32(rl.cfg.ConnLimit),
		BlacklistDurationNs: uint64(rl.cfg.BlacklistDuration) * 1_000_000_000,
	}
	return rl.objs.ConfigMap.Put(&key, &cfg)
}

// writeProtectedPorts writes the list of ports to protect
func (rl *RateLimiter) writeProtectedPorts() error {
	val := uint8(1)
	for _, port := range rl.cfg.TargetPorts {
		p := uint16(port)
		if err := rl.objs.ProtectedPortsMap.Put(&p, &val); err != nil {
			return fmt.Errorf("write port %d: %w", port, err)
		}
	}
	log.Printf("[XDP] Protected ports: %v", rl.cfg.TargetPorts)
	return nil
}
