package nfs

import "testing"

func TestPodStatsAddDelta(t *testing.T) {
	var p PodStats

	// First snapshot of a new cgroup counts in full
	first := IOStats{ReadBytes: 100, ReadCount: 2, ReadLatencyMaxNs: 50}
	p.addDelta(IOStats{}, first)

	// Second snapshot only adds the growth
	second := IOStats{ReadBytes: 250, ReadCount: 5, ReadLatencyMaxNs: 30}
	p.addDelta(first, second)

	if p.ReadBytes != 250 || p.ReadCount != 5 {
		t.Fatalf("got ReadBytes=%d ReadCount=%d, want 250 and 5", p.ReadBytes, p.ReadCount)
	}
	if p.ReadLatencyMaxNs != 50 {
		t.Fatalf("got ReadLatencyMaxNs=%d, want max of snapshots 50", p.ReadLatencyMaxNs)
	}

	// Another cgroup of the same Pod (e.g. a restarted container) adds on top
	p.addDelta(IOStats{}, IOStats{ReadBytes: 40})
	if p.ReadBytes != 290 {
		t.Fatalf("got ReadBytes=%d, want 290", p.ReadBytes)
	}
}

func TestPodStatsTotalsNeverDecrease(t *testing.T) {
	var p PodStats

	// A BPF entry evicted and recreated restarts from zero; totals must keep growing
	before := IOStats{WriteBytes: 1000}
	p.addDelta(IOStats{}, before)
	p.addDelta(before, IOStats{WriteBytes: 10})

	if p.WriteBytes != 1010 {
		t.Fatalf("got WriteBytes=%d, want 1010", p.WriteBytes)
	}
}
