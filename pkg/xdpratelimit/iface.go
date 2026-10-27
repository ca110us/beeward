package xdpratelimit

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// DetectMainInterface finds the network interface for the default route
// by parsing /proc/net/route. Returns the interface name and index.
func DetectMainInterface() (name string, index int, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", 0, fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		// Default route has Destination == 00000000
		if fields[1] == "00000000" {
			ifaceName := fields[0]
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return "", 0, fmt.Errorf("interface %s: %w", ifaceName, err)
			}
			return ifaceName, iface.Index, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", 0, fmt.Errorf("reading /proc/net/route: %w", err)
	}

	return "", 0, fmt.Errorf("no default route found")
}
