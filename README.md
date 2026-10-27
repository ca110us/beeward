<p align="center">
  <img src="assets/logo.svg" alt="Beeward logo" width="160">
</p>

<h1 align="center">Beeward</h1>

Beeward is an eBPF agent for Kubernetes nodes that watches over NFS/EFS I/O and wards off abusive traffic. It has two independent modules:

- **NFS/EFS I/O monitoring** — per-pod NFS throughput, IOPS and latency, traced in the kernel and exported as Prometheus metrics.
- **XDP rate limiter** — per-IP SYN rate limiting, concurrent connection limits and automatic blacklisting, enforced at the NIC before packets reach the network stack. Useful against SYN floods and connection-exhaustion attacks such as Slowloris.

Both modules run in a single DaemonSet and share one Prometheus endpoint. A failure in one module does not stop the other.

## Why Beeward

A shared NFS volume (Amazon EFS, Filestore, Azure Files, self-hosted NFS) is a common way to give many pods the same storage, especially across clouds. When it slows down or runs out of throughput, existing metrics can't say which pod is responsible: cloud providers report per file system, `node_exporter` reports per mount (and mounts of the same export share one client cache), and cAdvisor only covers block devices.

Beeward traces NFS reads and writes in the kernel and attributes them to the pod that issued them, so a noisy neighbor on a shared volume shows up directly in Prometheus.

## Quick Start

```bash
# Build and push the image (compilation happens inside the container, works on macOS)
make docker-push IMAGE_NAME=<your-registry>/beeward IMAGE_TAG=latest

# Edit deploy/daemonset.yaml (image, XDP settings), then deploy
make deploy

# Check metrics
kubectl -n beeward port-forward daemonset/beeward 9100:9100
curl -s http://localhost:9100/metrics | grep -E '^(nfs|xdp)_'
```

To run on a subset of nodes, label them and uncomment the `nodeSelector` in `deploy/daemonset.yaml`:

```bash
kubectl label node <node-name> beeward=enabled
```

## Configuration

All configuration is via environment variables.

### General

| Variable | Default | Description |
|---|---|---|
| `NODE_NAME` | `unknown` | Node name used as the `node` label (set from `spec.nodeName`) |
| `METRICS_PORT` | `9100` | Prometheus metrics port |
| `MONITOR_INTERVAL` | `60s` | How often NFS stats are collected |

### XDP rate limiter

| Variable | Default | Description |
|---|---|---|
| `XDP_ENABLED` | `false` | Set to `true` to enable the module |
| `XDP_TARGET_PORTS` | `443,80` | Destination ports to protect |
| `XDP_SYN_RATE_LIMIT` | `100` | Max SYN packets per second per source IP (token bucket rate and capacity) |
| `XDP_CONN_LIMIT` | `200` | Max concurrent TCP connections per source IP |
| `XDP_BLACKLIST_DURATION` | `600` | Seconds a source IP stays blocked after exceeding a limit |
| `XDP_WHITELIST_CIDRS` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Source CIDRs that bypass all checks |
| `XDP_PIN_PATH` | `/sys/fs/bpf/xdp_ratelimit` | Where BPF maps are pinned for inspection with `bpftool` |

> **Note:** With `hostNetwork` the program attaches to the host's main interface, so traffic is seen *after* the cloud load balancer. If your ingress is exposed through a NodePort Service, set `XDP_TARGET_PORTS` to the **NodePorts**, not the load balancer's external ports. Make sure the whitelist covers your pod, service and node CIDRs so in-cluster traffic is never limited.

## NFS/EFS Monitoring

### How it works

1. **Kernel hooks** — kprobes/kretprobes on `nfs_file_read` and `nfs_file_write` record bytes, operation counts and latency per cgroup (container). Latency is paired per thread, so concurrent calls don't interfere.
2. **Pod resolution** — each new cgroup is mapped to a pod UID once, by reading `/proc/<pid>/cgroup` for a PID recently seen in it, falling back to a cgroup inode search under `/sys/fs/cgroup` if that process has already exited.
3. **Aggregation** — per-cgroup growth is added to per-pod totals, so metrics only ever increase: short-lived processes exiting or containers restarting never make a counter go backwards, and a reused PID can't attribute I/O to the wrong pod.
4. **Cleanup** — when a pod's cgroup disappears its map entries and metrics are removed. Cgroups idle for an hour are evicted from the BPF map (their totals are kept), which bounds map usage.

No Kubernetes API access is required.

### Metrics

All labeled with `pod_uid` and `node`.

| Metric | Description |
|---|---|
| `nfs_read_bytes_total` / `nfs_write_bytes_total` | Cumulative bytes read / written |
| `nfs_read_ops_total` / `nfs_write_ops_total` | Cumulative read / write operations |
| `nfs_read_io_time_seconds_total` / `nfs_write_io_time_seconds_total` | Cumulative time spent in I/O |
| `nfs_read_latency_max_seconds` / `nfs_write_latency_max_seconds` | Max latency observed |

Example queries:

```promql
# Read throughput (bytes/sec)
rate(nfs_read_bytes_total{node="$node"}[5m])

# Read IOPS
rate(nfs_read_ops_total{node="$node"}[5m])

# Read busy percentage
rate(nfs_read_io_time_seconds_total{node="$node"}[5m]) * 100

# Average read latency (seconds)
rate(nfs_read_io_time_seconds_total{node="$node"}[5m]) / rate(nfs_read_ops_total{node="$node"}[5m])
```

## XDP Rate Limiter

### How it works

For every IPv4 TCP packet to a protected port:

1. **Whitelist** — source IPs matching `XDP_WHITELIST_CIDRS` (LPM trie) pass immediately.
2. **Blacklist** — blacklisted source IPs are dropped until their entry expires.
3. **SYN rate** — each SYN consumes a token from a per-IP token bucket refilled at `XDP_SYN_RATE_LIMIT` per second. An empty bucket blacklists the IP.
4. **Connection limit** — a per-IP counter is incremented on new connections and decremented by a TC egress program that watches outbound FIN/RST. Exceeding `XDP_CONN_LIMIT` blacklists the IP.

The program tries native XDP first and falls back to generic (SKB) mode if the driver does not support it. The main interface is detected from the default route in `/proc/net/route`. Non-TCP, non-IPv4 and unprotected-port traffic is always passed.

### Metrics

| Metric | Labels | Description |
|---|---|---|
| `xdp_ratelimit_packets` | `action` (`pass`, `drop_syn_rate`, `drop_conn_limit`, `drop_blacklist`) | Cumulative packets by verdict |
| `xdp_ratelimit_blacklist_size` | | IPs currently blacklisted |
| `xdp_ratelimit_blacklist_adds` | | Cumulative blacklist additions |
| `xdp_ratelimit_whitelist_hits` | | Cumulative whitelist hits |
| `xdp_ratelimit_whitelist_size` | | Number of whitelist CIDRs |
| `xdp_ratelimit_map_entries` | `map` | Current entries per BPF map |
| `xdp_ratelimit_config` | `param` | Active configuration values |

### Inspecting state

```bash
# On the node (or in the pod)
bpftool map dump pinned /sys/fs/bpf/xdp_ratelimit/blacklist_map
```

## Requirements

- Linux kernel with eBPF, kprobe and XDP support (5.x recommended)
- NFS client functions present in the kernel (`grep nfs_file /proc/kallsyms`) for the NFS module
- Pod privileges: `privileged: true`, `hostPID: true`, `hostNetwork: true`
- Host mounts: `/sys/kernel/debug` (kprobes) and `/sys/fs/bpf` (map pinning)

## Building

```bash
make docker-build                 # build image
make docker-push                  # build and push
make IMAGE_NAME=my/repo IMAGE_TAG=v1 docker-push
```

The Dockerfile installs clang/llvm/libbpf, runs `go generate` (bpf2go) and builds a static binary on a busybox base image.

## Troubleshooting

**No NFS metrics**

- Check NFS mounts exist on the node: `mount | grep nfs`
- Generate some I/O: `kubectl exec -it <pod> -- dd if=/dev/zero of=/mnt/nfs/test bs=1M count=10`
- Check logs: `kubectl -n beeward logs -l app=beeward --tail=100`

**eBPF programs fail to attach**

- Check the kernel version: `uname -r`
- Check the NFS symbols exist: `grep nfs_file /proc/kallsyms`

**High memory usage**

The NFS stats map holds up to 10240 cgroups and the latency maps up to 65536 in-flight calls. Adjust `MAX_CGROUPS` / `MAX_INFLIGHT` in [c/nfs_trace.bpf.c](c/nfs_trace.bpf.c) and rebuild.

## License

GPL-2.0 (required for eBPF programs using GPL-only helpers).
