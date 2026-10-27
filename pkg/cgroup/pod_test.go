package cgroup

import "testing"

func TestExtractCgroupPath(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "cgroup v2 - burstable pod",
			content: `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice/cri-containerd-abc123.scope`,
			want: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice",
		},
		{
			name: "cgroup v2 - guaranteed pod (no QoS layer)",
			content: `0::/kubepods.slice/kubepods-pod6910effd_ea14_4f76_a7de_53c333338acb.slice/cri-containerd-xyz789.scope`,
			want: "/sys/fs/cgroup/kubepods.slice/kubepods-pod6910effd_ea14_4f76_a7de_53c333338acb.slice",
		},
		{
			name: "cgroup v2 - besteffort pod",
			content: `0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod7589d90f_83af_4a05_a4ee_8bb078db72b8.slice/cri-containerd-def456.scope`,
			want: "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod7589d90f_83af_4a05_a4ee_8bb078db72b8.slice",
		},
		{
			name: "cgroup v1 - multiple lines (cpu controller)",
			content: `12:freezer:/
11:perf_event:/
10:pids:/kubepods/burstable/pod9b1e71e8-4787-4860-ab3c-8a8407bcff80/abc123
9:cpu,cpuacct:/kubepods/burstable/pod9b1e71e8-4787-4860-ab3c-8a8407bcff80/abc123
8:memory:/kubepods/burstable/pod9b1e71e8-4787-4860-ab3c-8a8407bcff80/abc123`,
			want: "/sys/fs/cgroup/kubepods/burstable/pod9b1e71e8-4787-4860-ab3c-8a8407bcff80",
		},
		{
			name:    "non-kubernetes cgroup - docker",
			content: `0::/system.slice/docker.service`,
			want:    "",
		},
		{
			name:    "containerd service (not a pod)",
			content: `0::/runtime.slice/containerd.service`,
			want:    "",
		},
		{
			name:    "root cgroup (not a pod)",
			content: `0::/`,
			want:    "",
		},
		{
			name:    "kubelet service (not a pod)",
			content: `0::/system.slice/kubelet.service`,
			want:    "",
		},
		{
			name:    "empty content",
			content: ``,
			want:    "",
		},
		{
			name: "cgroup v2 - without container scope",
			content: `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice`,
			want: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCgroupPath(tt.content)
			if got != tt.want {
				t.Errorf("extractCgroupPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePodUID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "cgroup v2 path with underscores",
			input: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice",
			want:  "9b1e71e8-4787-4860-ab3c-8a8407bcff80",
		},
		{
			name:  "cgroup v2 content with underscores",
			input: "0::/kubepods.slice/kubepods-burstable-pod9b1e71e8_4787_4860_ab3c_8a8407bcff80.slice/cri-containerd-abc.scope",
			want:  "9b1e71e8-4787-4860-ab3c-8a8407bcff80",
		},
		{
			name:  "cgroup v1 path with hyphens",
			input: "/kubepods/burstable/pod9b1e71e8-4787-4860-ab3c-8a8407bcff80/abc123",
			want:  "9b1e71e8-4787-4860-ab3c-8a8407bcff80",
		},
		{
			name:  "guaranteed pod",
			input: "kubepods-pod6910effd_ea14_4f76_a7de_53c333338acb.slice",
			want:  "6910effd-ea14-4f76-a7de-53c333338acb",
		},
		{
			name:  "no pod UID",
			input: "/system.slice/docker.service",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePodUID(tt.input)
			if got != tt.want {
				t.Errorf("parsePodUID() = %v, want %v", got, tt.want)
			}
		})
	}
}
