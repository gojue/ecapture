# Minimum Privileges Guide

eCapture requires elevated privileges to load eBPF programs and attach uprobes. This document describes the minimum Linux capabilities required and how to configure least-privilege access.

## Required Capabilities

### Kernel >= 5.8 (Recommended)

Starting from Linux 5.8, BPF-related capabilities were split from `CAP_SYS_ADMIN`:

| Capability | Purpose |
|------------|---------|
| `CAP_BPF` | Load and manage eBPF programs |
| `CAP_PERFMON` | Create perf events and read perf buffers (used for eBPF output) |
| `CAP_NET_ADMIN` | Required for TC (Traffic Control) attachment in pcapng mode |
| `CAP_SYS_PTRACE` | Required to access other processes' memory maps (reading `/proc/<pid>/maps`) |

### Kernel < 5.8

On older kernels, `CAP_BPF` and `CAP_PERFMON` do not exist. You need:

| Capability | Purpose |
|------------|---------|
| `CAP_SYS_ADMIN` | Encompasses BPF and perf capabilities on older kernels |
| `CAP_NET_ADMIN` | Required for TC attachment in pcapng mode |

### Summary by Mode

| eCapture Mode | Kernel >= 5.8 | Kernel < 5.8 |
|---------------|---------------|--------------|
| `text` | `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE` | `CAP_SYS_ADMIN` |
| `keylog` | `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE` | `CAP_SYS_ADMIN` |
| `pcapng` | `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN` + `CAP_SYS_PTRACE` | `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` |

## Configuration Methods

### Method 1: Using `sudo` (Simplest)

```bash
sudo ecapture tls
```

This grants full root privileges. It's the simplest approach but not the most secure.

### Method 2: Using `setcap` (Recommended for Repeated Use)

Grant specific capabilities to the eCapture binary:

```bash
# For kernel >= 5.8, text/keylog mode
sudo setcap 'cap_bpf,cap_perfmon,cap_sys_ptrace=eip' /usr/local/bin/ecapture

# For kernel >= 5.8, pcapng mode (additional cap_net_admin)
sudo setcap 'cap_bpf,cap_perfmon,cap_net_admin,cap_sys_ptrace=eip' /usr/local/bin/ecapture

# For kernel < 5.8
sudo setcap 'cap_sys_admin,cap_net_admin,cap_sys_ptrace=eip' /usr/local/bin/ecapture
```

After setting capabilities, you can run eCapture without `sudo`:

```bash
ecapture tls
```

> **Note**: `setcap` capabilities are stored in the file's extended attributes. If you replace or update the binary, you must re-apply `setcap`.

### Verify Capabilities

```bash
getcap /usr/local/bin/ecapture
# Expected output: /usr/local/bin/ecapture cap_bpf,cap_perfmon,cap_sys_ptrace=eip
```

### Method 3: Docker with Specific Capabilities

Instead of `--privileged=true` (which grants ALL capabilities and disables security restrictions), use specific capabilities:

```bash
# Kernel >= 5.8
docker run --rm \
  --cap-add=BPF \
  --cap-add=PERFMON \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_PTRACE \
  --pid=host \
  --net=host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  gojue/ecapture:latest tls

# Kernel < 5.8
docker run --rm \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_PTRACE \
  --pid=host \
  --net=host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  gojue/ecapture:latest tls
```

> **⚠️ Important**: Avoid `--privileged=true` in production. It grants the container **all** host capabilities and disables seccomp/AppArmor, which is a significant security risk.

### Required Volume Mounts for Docker

| Mount Path | Access | Purpose |
|------------|--------|---------|
| `/sys/kernel/debug` | Read-only | Access to debugfs for uprobe attachment |
| `/sys/fs/bpf` | Read-write | BPF filesystem for pinning maps |

### Required Docker Flags

| Flag | Purpose |
|------|---------|
| `--pid=host` | Access host process namespace (required to trace host processes) |
| `--net=host` | Access host network namespace (required for pcapng mode) |

## How eCapture Checks Capabilities

eCapture performs runtime capability detection at startup (see [`cli/cmd/env_detection.go`](../cli/cmd/env_detection.go)):

1. **Kernel version check**: Verifies minimum kernel version (x86_64: 4.18+, aarch64: 5.5+)
2. **Capability check**: Verifies the process has `CAP_BPF` (kernel >= 5.8) or `CAP_SYS_ADMIN` (kernel < 5.8)

If capabilities are insufficient, eCapture exits with a clear error message:

```
the current user does not have CAP_BPF to load bpf programs. 
Please run as root or use sudo or add the --privileged=true flag for Docker
```

## Security Best Practices

1. **Principle of Least Privilege**: Use `setcap` or Docker `--cap-add` instead of running as root
2. **Limit Scope**: Use `--pid` to target specific processes instead of system-wide capture
3. **Audit Usage**: Keep records of when and why eCapture is deployed
4. **Remove When Done**: Uninstall or remove capabilities after the auditing session
5. **File Permissions**: Restrict access to the eCapture binary

```bash
# Restrict binary access to a specific group
sudo chown root:security-audit /usr/local/bin/ecapture
sudo chmod 750 /usr/local/bin/ecapture
```

## Related Resources

- [Defense and Detection Guide](./defense-detection.md) — Detecting unauthorized eBPF tool usage
- [Linux Capabilities Manual](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

