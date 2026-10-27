package xdpratelimit

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// Config holds the XDP rate limiter configuration
type Config struct {
	SynRateLimit      int      // Max SYN packets per second per IP
	ConnLimit         int      // Max concurrent connections per IP
	BlacklistDuration int      // Blacklist duration in seconds
	WhitelistCIDRs    []string // CIDR ranges to whitelist
	TargetPorts       []int    // Ports to protect
	PinPath           string   // BPF map pin directory
}

// LoadConfig reads configuration from environment variables with defaults
func LoadConfig() *Config {
	cfg := &Config{
		SynRateLimit:      envInt("XDP_SYN_RATE_LIMIT", 100),
		ConnLimit:         envInt("XDP_CONN_LIMIT", 200),
		BlacklistDuration: envInt("XDP_BLACKLIST_DURATION", 600),
		WhitelistCIDRs:    envStringSlice("XDP_WHITELIST_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"),
		TargetPorts:       envIntSlice("XDP_TARGET_PORTS", "443,80"),
		PinPath:           envString("XDP_PIN_PATH", "/sys/fs/bpf/xdp_ratelimit"),
	}

	// Validate limits: non-positive values would disable or break rate limiting
	if cfg.SynRateLimit <= 0 {
		log.Printf("[XDP] WARNING: invalid XDP_SYN_RATE_LIMIT=%d, using default 100", cfg.SynRateLimit)
		cfg.SynRateLimit = 100
	}
	if cfg.ConnLimit <= 0 {
		log.Printf("[XDP] WARNING: invalid XDP_CONN_LIMIT=%d, using default 200", cfg.ConnLimit)
		cfg.ConnLimit = 200
	}
	if cfg.BlacklistDuration <= 0 {
		log.Printf("[XDP] WARNING: invalid XDP_BLACKLIST_DURATION=%d, using default 600", cfg.BlacklistDuration)
		cfg.BlacklistDuration = 600
	}

	// Validate ports: filter out-of-range values
	validPorts := make([]int, 0, len(cfg.TargetPorts))
	for _, p := range cfg.TargetPorts {
		if p >= 1 && p <= 65535 {
			validPorts = append(validPorts, p)
		} else {
			log.Printf("[XDP] WARNING: ignoring invalid port %d (must be 1-65535)", p)
		}
	}
	cfg.TargetPorts = validPorts

	return cfg
}

func envString(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envInt(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

func envStringSlice(key, defaultVal string) []string {
	v := os.Getenv(key)
	if v == "" {
		v = defaultVal
	}
	parts := strings.Split(v, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func envIntSlice(key, defaultVal string) []int {
	v := os.Getenv(key)
	if v == "" {
		v = defaultVal
	}
	parts := strings.Split(v, ",")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		result = append(result, n)
	}
	return result
}
