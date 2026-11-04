# Defense and Detection Guide

eCapture is a powerful security auditing tool. Like any security tool, it can be misused. This document provides guidance for security teams on how to detect unauthorized use of eCapture (or similar eBPF-based tools) and implement appropriate defenses.

## Detecting eBPF-based Capture Tools

### 1. Check Active eBPF Programs

```bash
# List all loaded eBPF programs (requires root)
sudo bpftool prog list

# Look for uprobe-type programs targeting SSL/TLS libraries
sudo bpftool prog list | grep -i uprobe
```

eCapture loads uprobe programs attached to functions like `SSL_read`, `SSL_write`, `SSL_do_handshake` in libraries such as `libssl.so`. Any unexpected uprobe programs targeting these functions should be investigated.

### 2. Check Uprobe Events

```bash
# Check registered uprobe events
sudo cat /sys/kernel/debug/tracing/uprobe_events

# Look for probes on SSL/TLS library functions
sudo cat /sys/kernel/debug/tracing/uprobe_events | grep -E "ssl|SSL|gnutls|nspr"
```

### 3. Check Active Perf Event Buffers

```bash
# List perf event arrays used by eBPF
sudo bpftool map list | grep -i perf
```

### 4. Monitor Process Execution

```bash
# Check for running eCapture processes
ps aux | grep ecapture

# Use auditd to monitor execution of eCapture
sudo auditctl -w /usr/local/bin/ecapture -p x -k ecapture_exec

# Monitor bpf() system calls (catches any eBPF tool)
sudo auditctl -a always,exit -F arch=b64 -S bpf -k bpf_activity
```

### 5. Check Docker Containers

```bash
# List privileged containers (eCapture requires --privileged or specific capabilities)
docker ps --format '{{.Names}}' | xargs -I {} docker inspect --format='{{.Name}}: Privileged={{.HostConfig.Privileged}}' {}
```

## Defense Strategies

### 1. Restrict eBPF Access

On systems where eBPF-based capture is not needed:

```bash
# Restrict unprivileged BPF (sysctl)
sudo sysctl -w kernel.unprivileged_bpf_disabled=1

# Make it persistent
echo "kernel.unprivileged_bpf_disabled=1" | sudo tee /etc/sysctl.d/99-disable-bpf.conf
```

### 2. Use Linux Security Modules

#### AppArmor

```bash
# Create an AppArmor profile that denies bpf() access
cat << 'EOF' > /etc/apparmor.d/deny-bpf
#include <tunables/global>
profile deny-bpf flags=(attach_disconnected) {
  # Deny BPF system call
  deny capability sys_admin,
  deny capability bpf,
  deny capability perfmon,
}
EOF
```

#### SELinux

```bash
# Audit BPF usage via SELinux
# Check for BPF-related AVC denials
ausearch -m AVC -ts today | grep bpf
```

### 3. Monitor with auditd

Create comprehensive audit rules for eBPF activity:

```bash
cat << 'EOF' > /etc/audit/rules.d/ebpf-monitor.rules
# Monitor bpf() system calls
-a always,exit -F arch=b64 -S bpf -k ebpf_usage

# Monitor perf_event_open (used by eBPF perf buffers)
-a always,exit -F arch=b64 -S perf_event_open -k perf_event

# Monitor access to tracing filesystem
-w /sys/kernel/debug/tracing/ -p rwa -k tracing_access

# Monitor uprobe registration
-w /sys/kernel/debug/tracing/uprobe_events -p wa -k uprobe_modification
EOF

sudo augenrules --load
```

### 4. Docker Security Hardening

Avoid granting full host access with `--privileged` when narrower permissions
meet the capture requirements. Capabilities and mounts depend on the kernel
and capture mode; use the [minimum privileges guide](minimum-privileges.md#method-3-docker-with-specific-capabilities)
as the shared deployment reference.

### 5. Network-level Detection

Inspect the addresses configured on the running process:

- `--listen` enables the HTTP runtime-configuration service; it is disabled
  by default. `127.0.0.1:28256` is an example address, not an always-open port.
- `--ecaptureq ws://host:port/` enables a WebSocket listener carrying Protobuf
  messages. It is also disabled by default; examples often use port `28257`.
- Network destinations in `--eventaddr` or `--logaddr` create outbound
  TCP/WebSocket connections to the configured receiver.

```bash
# Inspect listeners and established connections, then correlate their owners
# with the process configuration and authorized receivers.
sudo ss -tlnp
sudo ss -tnp
```

A fixed-port check cannot establish whether capture is active: the addresses
are configurable, and local file/stdout output needs no network listener.
See the [event forwarding API](event-forward-api.md) for channel formats.

## Responsible Use Guidelines

### For Security Teams

1. **Authorization**: Always obtain written authorization before deploying eCapture in production
2. **Scope**: Limit capture to specific processes using `--pid` flag instead of capturing all traffic
3. **Data Handling**: Captured plaintext may contain sensitive data (passwords, tokens, PII). Handle according to your organization's data classification policy
4. **Audit Trail**: Log when and where eCapture is used, by whom, and for what purpose
5. **Time Limits**: Remove eCapture after the audit/debugging session is complete

### For Organizations

1. **Policy**: Include eBPF-based tools in your security tool governance policy
2. **Training**: Ensure operators understand the data sensitivity implications
3. **Monitoring**: Deploy the detection mechanisms described above
4. **Incident Response**: Include unauthorized eBPF tool usage in your incident response playbook

## Related Resources

- [Linux eBPF Security](https://docs.kernel.org/bpf/bpf_design_QA.html) — Kernel documentation on eBPF security model
- [bpftool](https://github.com/libbpf/bpftool) — Inspection tool for eBPF programs and maps
- [Minimum Privileges Guide](./minimum-privileges.md) — eCapture least-privilege configuration

