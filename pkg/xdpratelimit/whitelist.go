package xdpratelimit

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf"
)

// WriteWhitelist parses CIDRs and writes them to the LPM trie whitelist map.
// IP addresses are stored in network byte order to match ip->saddr in XDP.
func WriteWhitelist(m *ebpf.Map, cidrs []string) error {
	count := 0
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[XDP] WARNING: invalid whitelist CIDR %q: %v", cidr, err)
			continue
		}

		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			log.Printf("[XDP] WARNING: IPv6 CIDR not supported, skipping: %s", cidr)
			continue
		}

		prefixLen, _ := ipNet.Mask.Size()

		// LPM trie key: prefixlen + IP in network byte order.
		// net.IP.To4() returns bytes in network order [0x0A, 0x00, 0x00, 0x00].
		// BPF LPM trie compares raw bytes in memory starting from byte 0.
		// ip->saddr in XDP also has network-order bytes in memory.
		// Use NativeEndian so the uint32 in memory has the SAME byte layout
		// as the original ip4 slice (preserving network byte order in memory).
		type lpmKey struct {
			Prefixlen uint32
			IP        uint32
		}
		key := lpmKey{
			Prefixlen: uint32(prefixLen),
			IP:        binary.NativeEndian.Uint32(ip4),
		}
		val := uint8(1)

		if err := m.Put(&key, &val); err != nil {
			return fmt.Errorf("add whitelist %s: %w", cidr, err)
		}
		count++
	}

	log.Printf("[XDP] Loaded %d whitelist CIDRs", count)
	XDPWhitelistSize.Set(float64(count))
	return nil
}
