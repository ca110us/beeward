package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var (
	podUIDRegex = regexp.MustCompile(`pod([a-f0-9_-]+)`)
)

// GetPodUID retrieves Pod UID from a process with fallback strategy
// Method 1: Read /proc/<pid>/cgroup (fast ~50μs, works if process alive)
// Method 2: Search /sys/fs/cgroup by inode (slow ~10-100ms, works even if process exited)
// Returns Pod UID and cgroup path (for cleanup), empty strings if not a Kubernetes pod
func GetPodUID(pid uint32, cgroupID uint64) (string, string) {
	// Method 1: Try /proc first (fast path)
	if podUID, cgroupPath := readPodUIDFromProc(pid); podUID != "" {
		return podUID, cgroupPath
	}

	// Method 2: Fallback to filesystem search
	return findPodUIDByCgroupID(cgroupID)
}

// readPodUIDFromProc reads /proc/<pid>/cgroup and extracts Pod UID
// Returns Pod UID and cgroup path, empty strings if not a Kubernetes pod or process exited
func readPodUIDFromProc(pid uint32) (string, string) {
	cgroupFilePath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupFilePath)
	if err != nil {
		return "", "" // Process may have exited
	}

	content := string(data)
	podUID := parsePodUID(content)
	if podUID == "" {
		return "", ""
	}

	// Extract cgroup path from content
	// Example line: "0::/kubepods.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice/cri-containerd-xxx.scope"
	// We want the directory part containing "pod"
	cgroupPath := extractCgroupPath(content)

	return podUID, cgroupPath
}

// findPodUIDByCgroupID finds Pod UID by searching cgroup filesystem using inode number
// This is slower (~10-100ms) but works even if the process has exited
// Implementation inspired by bpftrace's cgroup_path resolution
// See: https://github.com/bpftrace/bpftrace/pull/2055
// Returns Pod UID and cgroup path
func findPodUIDByCgroupID(cgroupID uint64) (string, string) {
	// cgroup_id is the inode number in cgroupfs
	// Walk /sys/fs/cgroup to find matching directory

	var foundPath string

	// Use filepath.Walk to traverse /sys/fs/cgroup
	// This is the same approach used by bpftrace
	err := filepath.Walk("/sys/fs/cgroup", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}

		// Only check directories
		if !info.IsDir() {
			return nil
		}

		// Performance optimization: Skip non-Kubernetes paths early
		if !strings.Contains(path, "kubepods") {
			// Still walk into /sys/fs/cgroup root and first level
			if path != "/sys/fs/cgroup" && !strings.HasPrefix(path, "/sys/fs/cgroup/kubepods") {
				return filepath.SkipDir
			}
			return nil
		}

		// Get file stat to check inode
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}

		// Check if inode matches cgroup_id
		if stat.Ino == cgroupID {
			// Found it! Check if it's a Kubernetes pod cgroup
			if strings.Contains(path, "pod") {
				foundPath = path
				return filepath.SkipAll // Stop walking, we found it
			}
		}

		return nil
	})

	if err != nil || foundPath == "" {
		return "", ""
	}

	// Extract Pod UID from path
	// Example: /sys/fs/cgroup/kubepods.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice
	podUID := parsePodUID(foundPath)
	return podUID, foundPath
}

// extractCgroupPath extracts the cgroup directory path from /proc/<pid>/cgroup content
// Supports both cgroup v1 and v2 formats:
// - v2 burstable/besteffort: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<UID>.slice/..."
// - v2 guaranteed: "0::/kubepods.slice/kubepods-pod<UID>.slice/..."
// - v1: "9:cpu:/kubepods/burstable/pod<UID>/container-id"
func extractCgroupPath(content string) string {
	// cgroup v2 format with QoS layer: kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<UID>.slice
	re := regexp.MustCompile(`(kubepods\.slice/kubepods-[^/]+\.slice/kubepods-[^/]*pod[a-f0-9_-]+\.slice)`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return "/sys/fs/cgroup/" + matches[1]
	}

	// cgroup v2 format without QoS layer (guaranteed): kubepods.slice/kubepods-pod<UID>.slice
	re = regexp.MustCompile(`(kubepods\.slice/kubepods-pod[a-f0-9_-]+\.slice)`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return "/sys/fs/cgroup/" + matches[1]
	}

	// cgroup v1 format: kubepods/qos/pod<UID>
	re = regexp.MustCompile(`(kubepods/[^/]+/pod[a-f0-9_-]+)`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return "/sys/fs/cgroup/" + matches[1]
	}

	return ""
}

// parsePodUID extracts Pod UID from a string (cgroup path or file content)
// Works for both:
// - File content: 0::/kubepods.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice
// - Directory path: /sys/fs/cgroup/kubepods.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice
func parsePodUID(s string) string {
	matches := podUIDRegex.FindStringSubmatch(s)
	if len(matches) > 1 {
		uid := strings.ReplaceAll(matches[1], "_", "-")
		return uid
	}
	return ""
}

// CgroupInfo stores Pod UID and cgroup path for cleanup
type CgroupInfo struct {
	PodUID      string
	CgroupPath  string // Path to cgroup directory (e.g., /sys/fs/cgroup/kubepods.slice/...)
}

// CgroupMapper maintains a mapping from cgroup_id to Pod info
// This is used to cache the Pod UID and track cgroup paths for cleanup
type CgroupMapper struct {
	mapping map[uint64]*CgroupInfo
}

// NewCgroupMapper creates a new cgroup ID to Pod info mapper
func NewCgroupMapper() *CgroupMapper {
	return &CgroupMapper{
		mapping: make(map[uint64]*CgroupInfo),
	}
}

// Get returns the Pod UID for a given cgroup ID
func (m *CgroupMapper) Get(cgroupID uint64) string {
	if info := m.mapping[cgroupID]; info != nil {
		return info.PodUID
	}
	return ""
}

// GetInfo returns the full CgroupInfo for a given cgroup ID
func (m *CgroupMapper) GetInfo(cgroupID uint64) *CgroupInfo {
	return m.mapping[cgroupID]
}

// Set stores a mapping from cgroup ID to Pod UID and cgroup path
func (m *CgroupMapper) Set(cgroupID uint64, podUID string, cgroupPath string) {
	m.mapping[cgroupID] = &CgroupInfo{
		PodUID:     podUID,
		CgroupPath: cgroupPath,
	}
}

// Delete removes a cgroup mapping
func (m *CgroupMapper) Delete(cgroupID uint64) {
	delete(m.mapping, cgroupID)
}

// Exists checks if a cgroup ID is already mapped
func (m *CgroupMapper) Exists(cgroupID uint64) bool {
	_, exists := m.mapping[cgroupID]
	return exists
}

// Len returns the number of cached mappings
func (m *CgroupMapper) Len() int {
	return len(m.mapping)
}

// GetAllCgroupIDs returns all tracked cgroup IDs
func (m *CgroupMapper) GetAllCgroupIDs() []uint64 {
	ids := make([]uint64, 0, len(m.mapping))
	for id := range m.mapping {
		ids = append(ids, id)
	}
	return ids
}
