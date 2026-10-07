# Performance benchmarks

eCapture has two complementary benchmark layers:

1. Go microbenchmarks measure the OpenSSL userspace decode and text-output
   pipeline without loading eBPF programs.
2. The Linux TLS benchmark measures application overhead and event loss through
   the real uprobe, perf-buffer, decoder, dispatcher, and file-writer path.

Do not use the microbenchmarks to claim kernel-side overhead or zero event
loss. Only the end-to-end benchmark exercises those paths.

## OpenSSL userspace microbenchmarks

Run on Linux from the repository root:

```bash
go test -run '^$' -bench '^BenchmarkTLSDataEvent' -benchmem \
  ./internal/probe/openssl
```

The benchmarks use a maximum-size 16 KiB TLS event and report allocations and
payload throughput for:

- binary event decode and validation;
- decode, validation, synchronous dispatch, text formatting, and a discard
  writer.

For comparisons, run each revision several times and analyze the results with
`benchstat`. Keep the CPU governor, Go version, build tags, and host load fixed.

## End-to-end OpenSSL benchmark

The maintained benchmark is modeled on [issue #990](https://github.com/gojue/ecapture/issues/990):
short-lived TLS connections, HTTP/1.1 `Connection: close`, a 96 KiB upload, and
a 10 ms launch interval. Each request and response carries a unique marker, so
the harness measures data-event completeness directly instead of inferring it
from request counts or log line totals.

### Requirements

- Linux x86_64 with kernel 4.18+ or Linux aarch64 with kernel 5.5+;
- root;
- a clean V2 build at `bin/ecapture`;
- `go`, `cc`, OpenSSL development files, `ldd`, and GNU userland tools.

Build eCapture before running the benchmark:

```bash
make clean
make all
sudo make benchmark-tls
```

The defaults run three paired baseline/capture trials with:

| Setting | Default | Meaning |
| --- | ---: | --- |
| `BENCH_REQUESTS` | `160` | short-lived requests per trial |
| `BENCH_CONCURRENCY` | `1` | clients allowed in each batch |
| `BENCH_PAYLOAD_BYTES` | `98304` | request body size (96 KiB) |
| `BENCH_DELAY_MS` | `10` | delay after each client launch |
| `BENCH_RUNS` | `3` | paired baseline/capture trials |
| `BENCH_MAP_PAGES` | `8192` | perf-reader pages per CPU passed to `--mapsize` |
| `BENCH_TLS_VERSION` | `tls13` | `tls12` or `tls13` |
| `BENCH_FAIL_ON_LOSS` | `0` | set to `1` for a zero-loss regression gate |
| `BENCH_ARTIFACT_ROOT` | `/tmp/ecapture-benchmark` | private result parent directory |

`BENCH_MAP_PAGES` is a page count, not a byte count. On a host with 4 KiB
pages, the default gives each perf reader a 32 MiB per-CPU buffer. This makes
the V2 unit explicit; a source-level byte constant from an older version must
not be copied into `--mapsize` without conversion.

For example, a concurrent saturation run is:

```bash
sudo BENCH_REQUESTS=1000 \
  BENCH_CONCURRENCY=64 \
  BENCH_DELAY_MS=0 \
  BENCH_RUNS=5 \
  make benchmark-tls
```

The harness starts a local Go TLS server and OpenSSL client, resolves the exact
`libssl.so` used by that client, and alternates an uninstrumented baseline with
eCapture text mode. It does not use a PID filter because every request is a new
process, matching the short-connection workload in issue #990. Run it on an
otherwise quiet host to avoid capturing unrelated users of the same library.

### Results

Every benchmark invocation preserves a mode-0700 artifact directory and writes:

- `summary.tsv`: wall time, requests/second, p50/p95/p99 request latency,
  captured request/response markers, marker loss, perf lost samples, and
  eCapture errors and CPU/RSS samples;
- `comparison.tsv`: capture-versus-baseline throughput and p99 deltas plus the
  loss/resource columns;
- per-request duration/error files;
- eCapture operational and plaintext event logs for each capture trial;
- server logs and the exact locally built fixtures;
- `environment.txt`: commit, benchmark settings, OS/kernel/CPU/memory,
  toolchain versions, eCapture version, and the linked OpenSSL library.

Negative `throughput_delta_pct` is overhead. Positive `p99_delta_pct` is added
tail latency. `marker_loss_pct` is calculated from unique request and response
markers, with `2 * BENCH_REQUESTS` expected per capture run.

Missing markers and nonzero `perf_lost_samples` are reported as benchmark data.
Set `BENCH_FAIL_ON_LOSS=1` to make either condition fail the command for a
regression gate. Client or fixture failures always fail the command because
their performance results are invalid.

The artifacts contain captured plaintext. Review and redact them before
sharing, and never commit them.

## Recording an environment

Include enough context to reproduce a result:

```bash
uname -a
cat /etc/os-release
lscpu
free -h
openssl version -a
git rev-parse HEAD
```

Also record all `BENCH_*` overrides, whether the build used CO-RE or non-CO-RE,
the eCapture/OpenSSL versions, VM or bare-metal status, and any CPU governor or
host-load controls.

Do not publish universal overhead ranges from a single machine. Uprobe cost,
perf-buffer pressure, output I/O, CPU count, kernel, OpenSSL call patterns, and
payload sizes all materially affect the result.
