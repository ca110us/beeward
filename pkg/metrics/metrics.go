package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// NFS metrics (using Gauge for cumulative counters)
	NFSReadBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_read_bytes_total",
			Help: "Cumulative bytes read from NFS by pod (use rate() for per-second)",
		},
		[]string{"pod_uid", "node"},
	)
	NFSWriteBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_write_bytes_total",
			Help: "Cumulative bytes written to NFS by pod (use rate() for per-second)",
		},
		[]string{"pod_uid", "node"},
	)
	NFSReadOps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_read_ops_total",
			Help: "Cumulative NFS read operations by pod (use rate() for ops/second)",
		},
		[]string{"pod_uid", "node"},
	)
	NFSWriteOps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_write_ops_total",
			Help: "Cumulative NFS write operations by pod (use rate() for ops/second)",
		},
		[]string{"pod_uid", "node"},
	)

	// NFS latency metrics (similar to node_disk_io_time_seconds_total)
	NFSReadIOTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_read_io_time_seconds_total",
			Help: "Cumulative time spent in NFS read I/O operations (use rate() to see I/O busy percentage)",
		},
		[]string{"pod_uid", "node"},
	)
	NFSWriteIOTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_write_io_time_seconds_total",
			Help: "Cumulative time spent in NFS write I/O operations (use rate() to see I/O busy percentage)",
		},
		[]string{"pod_uid", "node"},
	)
	NFSReadLatencyMax = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_read_latency_max_seconds",
			Help: "Maximum NFS read latency observed (useful for detecting slow operations)",
		},
		[]string{"pod_uid", "node"},
	)
	NFSWriteLatencyMax = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nfs_write_latency_max_seconds",
			Help: "Maximum NFS write latency observed (useful for detecting slow operations)",
		},
		[]string{"pod_uid", "node"},
	)
)

func init() {
	// Register NFS metrics
	prometheus.MustRegister(NFSReadBytes)
	prometheus.MustRegister(NFSWriteBytes)
	prometheus.MustRegister(NFSReadOps)
	prometheus.MustRegister(NFSWriteOps)
	prometheus.MustRegister(NFSReadIOTime)
	prometheus.MustRegister(NFSWriteIOTime)
	prometheus.MustRegister(NFSReadLatencyMax)
	prometheus.MustRegister(NFSWriteLatencyMax)
}

// StartServer starts the HTTP server for Prometheus metrics
func StartServer(port string) error {
	http.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(":"+port, nil)
}
