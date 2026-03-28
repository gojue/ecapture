# Performance Benchmarks

This document describes the performance characteristics of eCapture and provides a methodology for measuring overhead in your environment.

## Overview

eCapture uses eBPF uprobes to intercept function calls in userspace libraries (OpenSSL, GnuTLS, etc.). The performance overhead consists of:

1. **Uprobe Entry/Exit**: Kernel overhead for each intercepted function call (~1-2μs per event)
2. **eBPF Program Execution**: In-kernel data extraction (~0.1-0.5μs per event)
3. **Perf Buffer Transfer**: Copying data from kernel to userspace
4. **Userspace Processing**: Parsing, formatting, and writing captured data

## Benchmark Methodology

### Test Environment

To produce meaningful benchmarks, document your test environment:

```bash
# System information
uname -a
cat /proc/cpuinfo | head -20
free -h
cat /etc/os-release

# Kernel BTF support
ls -la /sys/kernel/btf/vmlinux

# OpenSSL version
openssl version
```

### Benchmark Tool: `wrk` + HTTPS Server

#### Setup

```bash
# Install wrk (HTTP benchmarking tool)
sudo apt-get install wrk

# Start an HTTPS server (using nginx or a simple Go server)
# Ensure it uses the system's OpenSSL/libssl
```

#### Baseline (Without eCapture)

```bash
# Run wrk for 60 seconds with 4 threads and 100 connections
wrk -t4 -c100 -d60s https://localhost:8443/
```

Record: Requests/sec, Latency (avg, p99), Transfer/sec.

#### With eCapture (Text Mode)

```bash
# Terminal 1: Start eCapture
sudo ecapture tls -m text --pid=<nginx_pid>

# Terminal 2: Run the same benchmark
wrk -t4 -c100 -d60s https://localhost:8443/
```

#### With eCapture (PcapNG Mode)

```bash
# Terminal 1: Start eCapture in pcapng mode
sudo ecapture tls -m pcap -i lo --pcapfile=/tmp/bench.pcapng --pid=<nginx_pid>

# Terminal 2: Run the same benchmark
wrk -t4 -c100 -d60s https://localhost:8443/
```

### Metrics to Collect

| Metric | How to Measure | Tool |
|--------|----------------|------|
| **CPU Overhead** | Compare CPU usage of target process with/without eCapture | `pidstat -p <pid> 1` |
| **eCapture CPU Usage** | CPU consumption of the eCapture process itself | `pidstat -p <ecapture_pid> 1` |
| **Memory Usage** | RSS of eCapture process | `ps -o rss= -p <ecapture_pid>` |
| **Request Latency Impact** | p50/p99 latency increase | `wrk --latency` |
| **Throughput Impact** | Requests/sec reduction | `wrk` output |
| **Event Loss Rate** | Perf buffer overflow events | eCapture log output (look for "lost events") |

### Automated Benchmark Script

```bash
#!/bin/bash
# benchmark.sh - eCapture performance benchmark
# Must run on Linux with kernel >= 4.18 (x86_64) or >= 5.5 (aarch64)

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: This script must run on Linux." >&2
    exit 1
fi

TARGET_URL="${1:?Usage: $0 <https_url> [pid]}"
TARGET_PID="${2:-}"
DURATION="60s"
THREADS=4
CONNECTIONS=100

echo "=== eCapture Performance Benchmark ==="
echo "Date: $(date -Iseconds)"
echo "Kernel: $(uname -r)"
echo "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "Target: ${TARGET_URL}"
echo ""

# Baseline
echo "--- Baseline (no eCapture) ---"
wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} --latency "${TARGET_URL}" | tee /tmp/bench_baseline.txt
echo ""

# With eCapture text mode
echo "--- With eCapture (text mode) ---"
PID_FLAG=""
if [[ -n "${TARGET_PID}" ]]; then
    PID_FLAG="--pid=${TARGET_PID}"
fi
sudo ecapture tls -m text ${PID_FLAG} &>/tmp/ecapture_bench.log &
ECAP_PID=$!
sleep 3  # Wait for eCapture to initialize

wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} --latency "${TARGET_URL}" | tee /tmp/bench_ecapture.txt

sudo kill ${ECAP_PID} 2>/dev/null || true
wait ${ECAP_PID} 2>/dev/null || true
echo ""

echo "=== Results saved to /tmp/bench_baseline.txt and /tmp/bench_ecapture.txt ==="
echo "=== Compare Requests/sec and Latency between the two runs ==="
```

## Expected Performance Characteristics

Based on the eBPF uprobe mechanism, the expected overhead profile is:

| Scenario | Expected Overhead | Notes |
|----------|-------------------|-------|
| **Low traffic** (< 100 req/s) | Negligible (< 1% CPU) | Uprobe cost amortized over few events |
| **Medium traffic** (100-1K req/s) | Low (1-3% CPU) | Perf buffer well within capacity |
| **High traffic** (1K-10K req/s) | Moderate (3-8% CPU) | May need to tune perf buffer size |
| **Very high traffic** (> 10K req/s) | Significant (> 10% CPU) | Risk of perf buffer overflow; use `--pid` to limit scope |

### Perf Buffer Sizing

eCapture's default perf buffer size is **4 MB** per CPU. Under high traffic, you may see "lost X events" messages. This indicates the userspace reader cannot keep up with kernel-side production.

Mitigation strategies:
- Use `--pid` to capture only specific processes
- Use `keylog` mode instead of `text` mode (less data per event)
- Increase perf buffer size (if supported by your eCapture version)

## Known Limitations

1. **Uprobe overhead scales with call frequency**: Each `SSL_read`/`SSL_write` call incurs overhead, regardless of data size
2. **No sampling**: eCapture captures all events; there is no probabilistic sampling mode
3. **Single-threaded userspace processing**: The event reader is currently single-threaded, which can become a bottleneck under very high load
4. **No backpressure**: If the userspace reader falls behind, events are dropped silently (perf buffer overflow)

## Contributing Benchmark Results

If you run benchmarks on your infrastructure, we welcome contributions! Please open a PR with:

1. Test environment details (CPU, memory, kernel version, OpenSSL version)
2. Benchmark methodology and commands used
3. Raw results (baseline and with eCapture)
4. Summary of findings

## Related Resources

- [eBPF Performance Overhead](https://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html) — Brendan Gregg's analysis of eBPF tracing overhead
- [Minimum Privileges Guide](./minimum-privileges.md) — Least-privilege configuration

