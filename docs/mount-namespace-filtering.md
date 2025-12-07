# Mount Namespace Filtering for Container Environments

## Overview

eCapture now supports mount namespace filtering, enabling precise capture of TLS/SSL traffic from specific containers in Kubernetes and Docker environments, even for short-lived processes.

## The Problem

In container environments, there's a fundamental conflict:

- **Short-lived processes** (< 1 second) require `--pid=0` to capture them before they exit
- **Multi-container environments** need process isolation to avoid capturing traffic from ALL containers
- Traditional `--pid=SPECIFIC_PID` approach misses short-lived processes because eCapture startup takes ~800-1000ms

## The Solution

Mount namespace filtering allows you to:
1. Use `--pid=0` to capture ALL processes (including short-lived ones)
2. Use `--mntns=<inode>` to filter events to a specific container's namespace
3. Use host library paths instead of container-specific paths

### How It Works

- **System-wide uprobes**: eCapture attaches to the host's library files once
- **Kernel-level filtering**: eBPF code filters events by mount namespace at the kernel level
- **Zero overhead**: No performance impact on other containers

## Usage

### Basic Usage

```bash
# 1. Get the container's mount namespace inode
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' CONTAINER_NAME)
MNTNS=$(sudo stat -c %i /proc/$CONTAINER_PID/ns/mnt)

# 2. Run eCapture with namespace filtering
sudo ./bin/ecapture tls \
  --pid=0 \
  --mntns=$MNTNS \
  --libssl=/usr/lib/x86_64-linux-gnu/libssl.so.1.1

```

### Kubernetes Usage

```bash
# 1. Get pod container ID
POD_NAME="my-pod"
CONTAINER_NAME="my-container"
CONTAINER_ID=$(kubectl get pod $POD_NAME -o jsonpath='{.status.containerStatuses[?(@.name=="'$CONTAINER_NAME'")].containerID}' | sed 's/.*:\/\///')

# 2. Get container PID (on the node where pod is running)
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_ID)

# 3. Get mount namespace inode
MNTNS=$(sudo stat -c %i /proc/$CONTAINER_PID/ns/mnt)

# 4. Run eCapture with namespace filtering
sudo ./bin/ecapture tls \
  --pid=0 \
  --mntns=$MNTNS \
  --libssl=/usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
  -m text
```

### Advanced: Helper Script

Create a helper script to automate namespace discovery:

```bash
#!/bin/bash
# capture-container.sh

CONTAINER_NAME=$1
if [ -z "$CONTAINER_NAME" ]; then
    echo "Usage: $0 <container_name>"
    exit 1
fi

# Get container PID
PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_NAME 2>/dev/null)
if [ -z "$PID" ] || [ "$PID" == "0" ]; then
    echo "Error: Container '$CONTAINER_NAME' not found or not running"
    exit 1
fi

# Get mount namespace inode
MNTNS=$(sudo stat -c %i /proc/$PID/ns/mnt 2>/dev/null)
if [ -z "$MNTNS" ]; then
    echo "Error: Could not read namespace for PID $PID"
    exit 1
fi

echo "Container: $CONTAINER_NAME"
echo "PID: $PID"
echo "Mount NS: $MNTNS"
echo ""
echo "Running eCapture..."

# Run eCapture with namespace filtering
sudo ecapture tls \
  --pid=0 \
  --mntns=$MNTNS \
  --libssl=/usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
  -m text
```

Usage:
```bash
chmod +x capture-container.sh
./capture-container.sh my-container
```

## Configuration Options

### --mntns Flag

```
--mntns uint
    if mntns is 0 then we target all mount namespaces
    Use to capture specific containers: --mntns=$(stat -c %i /proc/PID/ns/mnt)
    (default 0)
```

### Combined with Other Flags

```bash
# Capture only UID 1000 in specific namespace
ecapture tls --pid=0 --uid=1000 --mntns=4026532573

# Capture with keylog output
ecapture tls --pid=0 --mntns=4026532573 -m keylog -k keys.log

# Capture with pcap output
ecapture tls --pid=0 --mntns=4026532573 -m pcap -w output.pcapng -i eth0
```

## Supported Modules

Mount namespace filtering is supported in:
- ✅ `tls` (OpenSSL)
- ✅ `gnutls` (GnuTLS)  
- ✅ `gotls` (Go TLS) - *experimental*
- ✅ `nspr` (NSS/NSPR)

## Requirements

- **Kernel**: 5.2+ (for eBPF global variables support, required by `target_mntns` constant)
  - Note: Other eCapture features work on older kernels (4.18+ x86_64, 5.5+ aarch64)
  - Mount namespace filtering specifically requires 5.2+ for global variable support
- **Root**: Required for eBPF and namespace access
- **CO:RE**: Strongly recommended for portable namespace access across kernel versions
  - Non-CO:RE builds use kernel-version-specific offsets (tested on 5.10-6.11)

## Troubleshooting

### "target all mount namespaces" Message

If you see this in the logs, it means `--mntns` was not set or set to 0:
```
INFO target all mount namespaces.
```

Solution: Ensure you're passing a non-zero namespace inode value.

### Wrong Container Being Captured

Check that you're using the correct namespace inode:
```bash
# Verify namespace
sudo ls -l /proc/PID/ns/mnt
# Output: lrwxrwxrwx ... mnt:[4026532573]
#                              ^^^^^^^^^^^ This is your MNTNS value
```

### No Events Captured

1. Verify the container is making HTTPS requests:
```bash
docker exec CONTAINER_NAME curl -v https://example.com
```

2. Check if the correct SSL library is being used:
```bash
docker exec CONTAINER_NAME ldd /usr/bin/curl | grep ssl
```

3. Ensure eCapture is using the correct library path:
```bash
# Find where libssl is in the host system (not container)
find /usr/lib /lib -name "libssl.so*" 2>/dev/null
```

### Performance Considerations

Mount namespace filtering has minimal overhead:
- **Kernel-side filtering**: Events are dropped at eBPF level before reaching user-space
- **No container impact**: Containers without matching namespace are not affected
- **Single uprobe**: Only one uprobe per library, shared across all containers

## How It Compares to Other Methods

| Method | Short-Lived Processes | Multi-Container | Performance |
|--------|----------------------|-----------------|-------------|
| `--pid=0` (no mntns) | ✅ | ❌ | ⚠️ High overhead |
| `--pid=SPECIFIC_PID` | ❌ | ✅ | ✅ Low overhead |
| **`--pid=0 --mntns=...`** | **✅** | **✅** | **✅ Low overhead** |

## Technical Details

### eBPF Implementation

The namespace filtering is implemented in the eBPF probes:

```c
// Check mount namespace filtering
if (target_mntns != 0) {
    u64 mntns = get_mnt_ns_id();
    if (mntns != target_mntns) {
        return 0;  // Skip this event
    }
}
```

The `get_mnt_ns_id()` function uses BPF CO:RE to read the current task's mount namespace ID:

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
unsigned int inum = BPF_CORE_READ(mnt_ns, ns.inum);
```

### Why Mount Namespace?

We use mount namespace (not PID namespace) because:
1. Mount namespaces are stable throughout container lifetime
2. They identify the container's filesystem view
3. They're accessible from kernel context
4. They survive process exits

## Examples

### Example 1: Capture curl in Docker container

```bash
# Start a container with repeating curl
docker run -d --name test-curl debian bash -c \
  'apt-get update && apt-get install -y curl && \
   while true; do curl -s https://example.com; sleep 5; done'

# Get namespace
MNTNS=$(sudo stat -c %i /proc/$(docker inspect -f '{{.State.Pid}}' test-curl)/ns/mnt)

# Capture
sudo ecapture tls --pid=0 --mntns=$MNTNS --libssl=/usr/lib/x86_64-linux-gnu/libssl.so.1.1
```

### Example 2: Kubernetes Pod Traffic

```bash
# On the Kubernetes node
POD_PID=$(docker inspect -f '{{.State.Pid}}' $(kubectl get pod POD_NAME -o jsonpath='{.status.containerStatuses[0].containerID}' | cut -d'/' -f3))
MNTNS=$(sudo stat -c %i /proc/$POD_PID/ns/mnt)

# Capture to file
sudo ecapture tls --pid=0 --mntns=$MNTNS \
  --libssl=/usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
  -l /var/log/ecapture/pod-traffic.log
```

## Future Enhancements

Potential improvements:
- [ ] Namespace name resolution (container name from namespace ID)
- [ ] Multiple namespace filtering (--mntns=NS1,NS2,NS3)
- [ ] Automatic library path detection per namespace
- [ ] CGroup-based filtering integration
- [ ] User-friendly container selection (by name/ID instead of namespace)

## References

- [Issue #862](https://github.com/gojue/ecapture/issues/862) - Short-lived process capture
- [Issue #863](https://github.com/gojue/ecapture/issues/863) - Multi-container environments
- Linux Namespaces: `man 7 namespaces`
- BPF CO:RE: https://nakryiko.com/posts/bpf-portability-and-co-re/
