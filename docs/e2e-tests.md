# eCapture End-to-End (E2E) Tests

This document describes the comprehensive end-to-end test suite for eCapture modules.

## Overview

The e2e test suite validates that eCapture can successfully capture various types of system activity:

### Simple Probe Modules
- **Bash Module** (`bash`): Tests bash command capture
- **Zsh Module** (`zsh`): Tests zsh command capture
- **MySQL Module** (`mysqld`): Tests MySQL query capture
- **PostgreSQL Module** (`postgres`): Tests PostgreSQL query capture

### TLS/SSL Modules
- **TLS Module** (`tls`): Tests OpenSSL/BoringSSL traffic capture
- **GnuTLS Module** (`gnutls`): Tests GnuTLS library traffic capture
- **GoTLS Module** (`gotls`): Tests Go's native TLS implementation capture

## Prerequisites

### System Requirements

1. **Kernel Version**: Linux kernel >= 4.18 (x86_64) or >= 5.5 (aarch64)
2. **Root Access**: Tests must run with root/sudo privileges for eBPF operations
3. **Capabilities**: `CAP_SYS_ADMIN` and `CAP_BPF` (on newer kernels)

### Required Tools

All modules:
- `openssl` - For certificate generation
- `nc` (netcat) - For port checking
- `go` - Go compiler (1.24 or newer)
- `clang` - Clang compiler (version 12 or newer)

Module-specific:
- **Bash test**: bash shell
- **Zsh test**: zsh shell (optional)
- **MySQL test**: mysql client, MySQL/MariaDB server (optional)
- **PostgreSQL test**: psql client, PostgreSQL server (optional)
- **TLS/GnuTLS tests**: `python3`, `curl`
- **GnuTLS test**: `wget` (optional, for GnuTLS-based client)
- **GoTLS test**: Go compiler for building test server/client

### Optional Requirements

- `libgnutls30` or `libgnutls28` - GnuTLS library (for GnuTLS test)
- `libssl1.1` or `libssl3` - OpenSSL library (for TLS test)

## Running Tests

### Quick Start

Run all e2e tests:
```bash
sudo make e2e
```

### Individual Module Tests

Run specific module tests:

```bash
# Simple probe tests
sudo make e2e-bash      # Test Bash command capture
sudo make e2e-zsh       # Test Zsh command capture (requires zsh)
sudo make e2e-mysql     # Test MySQL query capture (requires MySQL/MariaDB)
sudo make e2e-postgres  # Test PostgreSQL query capture (requires PostgreSQL)

# TLS/SSL probe tests
sudo make e2e-tls       # Test TLS/OpenSSL capture
sudo make e2e-gnutls    # Test GnuTLS capture
sudo make e2e-gotls     # Test GoTLS capture
```

### Direct Script Execution

You can also run test scripts directly:

```bash
# Make sure scripts are executable
chmod +x test/e2e/*.sh

# Run individual tests
sudo bash test/e2e/bash_e2e_test.sh
sudo bash test/e2e/zsh_e2e_test.sh
sudo bash test/e2e/mysql_e2e_test.sh
sudo bash test/e2e/postgres_e2e_test.sh
sudo bash test/e2e/tls_e2e_test.sh
sudo bash test/e2e/gnutls_e2e_test.sh
sudo bash test/e2e/gotls_e2e_test.sh
```

## Test Architecture

### Test Flow

Each e2e test follows this general flow:

1. **Prerequisites Check**
   - Verify root privileges
   - Check kernel version
   - Verify required tools are installed

2. **Build Phase**
   - Build eCapture binary (if not present)
   - Build test programs (for GoTLS test)

3. **Execution Phase**
   - Launch eCapture module in background
   - Wait for initialization (2-3 seconds)
   - Execute HTTPS client requests to https://github.com
   - Capture output for analysis

4. **Verification Phase**
   - Check eCapture captured data
   - Verify plaintext content is visible
   - Validate HTTPS client succeeded

5. **Cleanup Phase**
   - Stop eCapture process
   - Remove temporary files
   - Display logs on failure

### Test Components

#### Common Utilities (`test/e2e/common.sh`)

Shared functions for all tests:
- Logging with color-coded output
- Root privilege checking
- Kernel version validation
- Process management (kill by pattern)
- Output verification

#### Simple Probe Tests

**Bash Test** (`test/e2e/bash_e2e_test.sh`)
- **Target**: Current bash processes
- **Client**: bash shell execution
- **Validates**: Bash command capture via readline hooks

**Zsh Test** (`test/e2e/zsh_e2e_test.sh`)
- **Target**: Zsh shell processes
- **Client**: zsh shell execution
- **Validates**: Zsh command capture
- **Note**: Requires zsh to be installed

**MySQL Test** (`test/e2e/mysql_e2e_test.sh`)
- **Target**: MySQL/MariaDB server
- **Client**: mysql command-line client
- **Validates**: MySQL query capture
- **Note**: Requires MySQL/MariaDB server running

**PostgreSQL Test** (`test/e2e/postgres_e2e_test.sh`)
- **Target**: PostgreSQL server
- **Client**: psql command-line client
- **Validates**: PostgreSQL query capture
- **Note**: Requires PostgreSQL server running

#### TLS/SSL Probe Tests

**TLS Test** (`test/e2e/tls_e2e_test.sh`)
- **Target**: https://github.com
- **Client**: curl (uses system OpenSSL/BoringSSL)
- **Validates**: OpenSSL/BoringSSL plaintext capture

**GnuTLS Test** (`test/e2e/gnutls_e2e_test.sh`)
- **Target**: https://github.com
- **Client**: wget (may use GnuTLS) or curl (fallback)
- **Validates**: GnuTLS plaintext capture
- **Note**: Requires GnuTLS library installed for full test

**GoTLS Test** (`test/e2e/gotls_e2e_test.sh`)
- **Target**: https://github.com
- **Client**: Custom Go HTTPS client (`test/e2e/go_https_client.go`)
- **Validates**: Go crypto/tls plaintext capture

## Test Output

### Success Output

When tests pass, you'll see:
```
[INFO] === TLS E2E Test ===
[INFO] === Step 1: Prerequisites Check ===
[INFO] Kernel version: 5.15.0 (OK)
[INFO] All required tools are present
...
[SUCCESS] ✓ TLS E2E test PASSED
[SUCCESS] eCapture successfully captured TLS plaintext traffic
```

### Failure Output

On failure, tests display:
- Error messages with context
- Complete server logs
- eCapture output logs
- Client request logs

Example:
```
[ERROR] Test failed. Showing logs:
=== Server Log ===
...
=== eCapture Log ===
...
=== Client Log ===
...
```

## Expected Behavior

### What Tests Validate

1. **eCapture starts successfully** without errors
2. **HTTPS server** accepts connections
3. **HTTPS client** completes requests successfully
4. **Plaintext capture** shows HTTP headers/body in eCapture output
5. **No crashes** during capture operation

### Known Limitations

1. **External Dependency**: Tests connect to https://github.com
   - Requires internet connectivity
   - May fail if GitHub is unreachable

2. **GnuTLS Test**: wget/curl may use OpenSSL instead of GnuTLS
   - To test GnuTLS fully, use applications that link to libgnutls
   - Test still validates eCapture's GnuTLS module can start and capture

3. **Timing Sensitivity**: Tests use sleep delays for process startup
   - May need adjustment on slow systems

4. **Output Formats**: eCapture output format may vary by:
   - Capture mode (text vs. keylog vs. pcap)
   - Library version
   - Traffic patterns

## Troubleshooting

### Common Issues

#### 1. Permission Denied
```
[ERROR] This test requires root privileges
```
**Solution**: Run with `sudo`:
```bash
sudo make e2e-tls
```

#### 2. Kernel Too Old
```
[ERROR] Kernel version 4.15.0 is too old. Required: >= 4.18
```
**Solution**: Upgrade kernel or use a newer system

#### 3. Missing Tools
```
[ERROR] Missing required tools: curl python3
```
**Solution**: Install required packages:
```bash
# Ubuntu/Debian
sudo apt-get install curl python3 openssl netcat-openbsd

# RHEL/CentOS
sudo yum install curl python3 openssl nc
```

#### 4. Port Already in Use
```
[ERROR] Port 8443 did not open within 10s
```
**Solution**: Check if port is in use:
```bash
sudo netstat -tlnp | grep 8443
# Kill the process using the port
sudo kill <pid>
```

#### 5. Build Failures
```
[ERROR] Failed to build ecapture
```
**Solution**: Check build requirements:
```bash
# Install build dependencies
sudo apt-get install clang llvm libelf-dev pkg-config golang-go

# Try manual build
make clean
make all
```

#### 6. eCapture Process Dies
```
[ERROR] eCapture process died
```
**Solution**: Check logs and system support:
- Verify eBPF is enabled in kernel
- Check dmesg for BPF-related errors: `sudo dmesg | grep -i bpf`
- Ensure kernel has BTF support: `ls /sys/kernel/btf/vmlinux`

### Debug Mode

For more verbose output, you can:

1. **View logs directly**:
```bash
# Logs are in /tmp/ecapture_*_e2e_*/output/
ls -la /tmp/ecapture_*_e2e_*/output/
```

2. **Run eCapture manually**:
```bash
# Run in foreground to see output
sudo ./bin/ecapture tls -m text
```

3. **Check eCapture help**:
```bash
./bin/ecapture tls -h
./bin/ecapture gnutls -h
./bin/ecapture gotls -h
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm libelf-dev pkg-config \
                                  golang-go curl python3 openssl netcat-openbsd
      
      - name: Run E2E tests
        run: |
          sudo make e2e
```

### Docker Testing

Run tests in Docker with privileged mode:

```bash
docker run --rm -it --privileged \
  -v "$(pwd)":/src -w /src \
  ubuntu:22.04 /bin/bash -c "
    apt-get update && \
    apt-get install -y build-essential clang llvm libelf-dev \
                       pkg-config golang-go git libpcap-dev \
                       bpftool ca-certificates curl python3 openssl netcat-openbsd && \
    make all && \
    make e2e
  "
```

## Extending Tests

### Adding New Tests

To add a new e2e test:

1. Create test script: `test/e2e/mymodule_e2e_test.sh`
2. Source common utilities: `source "$SCRIPT_DIR/common.sh"`
3. Implement test flow (see existing tests as templates)
4. Add Makefile target:
```makefile
.PHONY: e2e-mymodule
e2e-mymodule:
	bash ./test/e2e/mymodule_e2e_test.sh
```
5. Update `e2e` target to include new test

### Test Best Practices

1. **Use localhost only** - No external network dependencies
2. **Set reasonable timeouts** - Balance speed vs. reliability
3. **Make tests idempotent** - Can run multiple times safely
4. **Proper cleanup** - Always use trap handlers
5. **Log verbosely** - Help debug failures
6. **Use temporary directories** - Under `/tmp` for artifacts
7. **Check prerequisites** - Fail fast with clear error messages

## Performance Considerations

- **Test duration**: Each test takes ~10-20 seconds
- **Disk usage**: Minimal (~5-10 MB temporary files)
- **CPU usage**: Brief spikes during build and capture
- **Network**: Localhost only (no external traffic)

## Security Notes

- Tests require root privileges for eBPF operations
- Self-signed certificates are generated for testing only
- All traffic is localhost-only
- Temporary files are cleaned up after tests
- No sensitive data is logged or persisted

## Contributing

When modifying e2e tests:

1. Test changes locally with `sudo make e2e`
2. Ensure all three module tests pass
3. Update this documentation if adding features
4. Follow existing test patterns and style
5. Add comments for complex logic

## Support

For issues or questions:

1. Check troubleshooting section above
2. Review test logs in `/tmp/ecapture_*_e2e_*/output/`
3. Open issue on GitHub with:
   - Kernel version (`uname -r`)
   - OS version (`cat /etc/os-release`)
   - Test output/logs
   - Steps to reproduce

## References

- [eCapture README](../README.md)
- [eBPF Documentation](https://ebpf.io/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [GnuTLS Documentation](https://www.gnutls.org/documentation.html)
- [Go crypto/tls Package](https://pkg.go.dev/crypto/tls)
