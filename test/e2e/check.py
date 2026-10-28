#!/usr/bin/env python3
"""End-to-end check: NFS I/O is attributed to the right pod and never decreases.

Polls the Beeward metrics endpoint while the workload in workload.yaml runs.
Pod UIDs come from kubectl, or from --pods name=uid,... when there is no
cluster (test/vm emulates pods with cgroups).
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request

METRICS_URL = "http://127.0.0.1:9100/metrics"
TIMEOUT_SECONDS = 240
MiB = 1024 * 1024

# Exact bytes each pod reads/writes (see workload.yaml)
EXPECTED = {
    "writer-a": {"nfs_write_bytes_total": 30 * MiB},
    "writer-b": {"nfs_write_bytes_total": 60 * MiB},
    "reader-c": {"nfs_write_bytes_total": 10 * MiB, "nfs_read_bytes_total": 20 * MiB},
}

SAMPLE = re.compile(r'^(nfs_\w+)\{([^}]*)\} (\S+)$')
LABEL = re.compile(r'(\w+)="([^"]*)"')


def scrape():
    """Return {(metric, pod_uid): value} for all nfs_* samples."""
    with urllib.request.urlopen(METRICS_URL, timeout=5) as resp:
        text = resp.read().decode()
    samples = {}
    for line in text.splitlines():
        m = SAMPLE.match(line)
        if m:
            labels = dict(LABEL.findall(m.group(2)))
            samples[(m.group(1), labels.get("pod_uid", ""))] = float(m.group(3))
    return samples


def workload_pods():
    """Return {name: (uid, ready)} for the e2e workload pods."""
    out = subprocess.check_output(
        ["kubectl", "get", "pods", "-l", "app=nfs-e2e", "-o", "json"])
    pods = {}
    for item in json.loads(out)["items"]:
        conditions = item["status"].get("conditions", [])
        ready = any(c["type"] == "Ready" and c["status"] == "True" for c in conditions)
        pods[item["metadata"]["name"]] = (item["metadata"]["uid"], ready)
    return pods


def report(pods, samples):
    for name, expected in EXPECTED.items():
        uid = pods.get(name, ("?", False))[0]
        for metric, want in expected.items():
            got = samples.get((metric, uid), 0)
            print(f"  {name:9} {metric:22} got {got / MiB:7.2f} MiB, want {want / MiB:.2f} MiB")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pods", help="name=uid,... instead of looking pods up with kubectl")
    args = parser.parse_args()

    static_pods = None
    if args.pods:
        static_pods = {}
        for pair in args.pods.split(","):
            name, uid = pair.split("=")
            static_pods[name] = (uid, True)

    history = {}
    deadline = time.time() + TIMEOUT_SECONDS
    pods, samples = {}, {}

    while time.time() < deadline:
        try:
            samples = scrape()
        except OSError as err:
            print(f"metrics not reachable yet: {err}")
            time.sleep(2)
            continue

        # Counters must never go backwards, for any pod
        for key, value in samples.items():
            if value < history.get(key, 0):
                print(f"FAIL: {key[0]} for pod {key[1]} decreased from {history[key]} to {value}")
                return 1
            history[key] = value

        pods = static_pods or workload_pods()
        if set(pods) != set(EXPECTED) or not all(ready for _, ready in pods.values()):
            time.sleep(2)
            continue

        done = True
        for name, expected in EXPECTED.items():
            uid = pods[name][0]
            for metric, want in expected.items():
                got = samples.get((metric, uid), 0)
                if got > want:
                    print(f"FAIL: {name} {metric} over-counted")
                    report(pods, samples)
                    return 1
                done = done and got == want
        if done:
            print("PASS: per-pod NFS bytes match exactly and never decreased")
            report(pods, samples)
            return 0
        time.sleep(2)

    print(f"FAIL: expected values not reached within {TIMEOUT_SECONDS}s")
    report(pods, samples)
    return 1


if __name__ == "__main__":
    sys.exit(main())
