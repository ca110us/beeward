#!/bin/bash
# Runs inside an LVH VM with the kernel under test. Mounts NFS from the
# runner, emulates three pods with Kubernetes-style (systemd driver) cgroups,
# then starts Beeward and a workload with known I/O in the background.
# test/e2e/check.py on the runner verifies the metrics.
set -euxo pipefail

NFS_SERVER=$1
uname -r

apt-get update -q
apt-get install -y -q nfs-common
gcc -O2 -o /usr/local/bin/sendfile-read /host/test/vm/sendfile.c

# Start Beeward before anything is mounted, like on a fresh node
setsid env NODE_NAME=vm MONITOR_INTERVAL=2s METRICS_PORT=9100 \
  XDP_ENABLED=true XDP_TARGET_PORTS=18080 \
  /host/beeward > /tmp/beeward.log 2>&1 < /dev/null &

mkdir -p /mnt/nfs
mount -t nfs "$NFS_SERVER:/srv/nfs" /mnt/nfs

# pod_cgroup UID CONTAINER: create a pod's container cgroup, print its path
pod_cgroup() {
  local cg="/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod${1//-/_}.slice/cri-containerd-$2.scope"
  mkdir -p "$cg"
  echo "$cg"
}

A=$(pod_cgroup 11111111-1111-1111-1111-111111111111 aaaa)
B=$(pod_cgroup 22222222-2222-2222-2222-222222222222 bbbb)
C=$(pod_cgroup 33333333-3333-3333-3333-333333333333 cccc)

# Same I/O as test/e2e/workload.yaml, each command run inside a pod's cgroup
cat > /tmp/workload.sh <<EOF
set -ex
in_pod() { cg=\$1; shift; sh -c 'echo \$\$ > "\$0/cgroup.procs" && exec "\$@"' "\$cg" "\$@"; }

# Give Beeward a collection interval to attach its probes
sleep 5
for i in 1 2 3; do
  in_pod $A dd if=/dev/zero of=/mnt/nfs/a-\$i bs=1M count=10 conv=fsync
  sleep 3
done
in_pod $B dd if=/dev/zero of=/mnt/nfs/b bs=1M count=60 conv=fsync
in_pod $C dd if=/dev/zero of=/mnt/nfs/c bs=1M count=10 conv=fsync
in_pod $C dd if=/mnt/nfs/c of=/dev/null bs=1M
in_pod $C sendfile-read /mnt/nfs/c
touch /tmp/workload-done
EOF
setsid bash /tmp/workload.sh > /tmp/workload.log 2>&1 < /dev/null &
