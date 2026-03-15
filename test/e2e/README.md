# eCapture E2E Test Suite Documentation

This document describes the comprehensive End-to-End (E2E) test suite for the eCapture project.

## Overview

The E2E test suite validates eCapture's functionality across all 8 core modules and various parameter combinations. Tests are designed to run on Linux systems with root privileges and appropriate kernel versions.

## Prerequisites

### System Requirements
- **OS**: Linux (kernel x86_64 ≥ 4.18 or aarch64 ≥ 5.5)
- **Privileges**: ROOT access required
- **Tools**: curl, go, bash, and optionally: mysql, postgresql, zsh, tshark, tcpdump

### Building eCapture
```bash
make all         # Build with eBPF CO-RE support
# or
make nocore      # Build without CO-RE (fallback)
```

## Test Structure

### Test Categories

#### 1. Basic Tests (`test/e2e/*_e2e_test.sh`)
Original basic functionality tests for each module:
- `bash_e2e_test.sh` - Basic Bash command capture
- `zsh_e2e_test.sh` - Basic Zsh command capture  
- `mysql_e2e_test.sh` - Basic MySQL query capture
- `postgres_e2e_test.sh` - Basic PostgreSQL query capture
- `tls_e2e_test.sh` - Basic TLS text/pcap/keylog modes
- `gnutls_e2e_test.sh` - Basic GnuTLS capture
- `gotls_e2e_test.sh` - Basic GoTLS capture

#### 2. Advanced Tests (`test/e2e/*_advanced_test.sh`)
Comprehensive tests with parameter variations and edge cases:

**TLS Module Advanced Tests**:
- `tls_text_advanced_test.sh` - 8 tests
  - HTTP/1.1 and HTTP/2 capture
  - PID and UID filtering
  - Concurrent connections
  - Text truncation (-t parameter)
  - Debug mode (-d)
  - Hex output (--hex)

- `tls_pcap_advanced_test.sh` - 8 tests
  - Basic pcapng mode
  - Port and host filters
  - Network interface specification (-i)
  - Concurrent connections
  - PID filtering
  - Tshark compatibility verification
  - Mapsize configuration (--mapsize)

- `tls_keylog_advanced_test.sh` - 8 tests
  - Basic keylog mode
  - TLS 1.2 and TLS 1.3 capture
  - Concurrent connections
  - PID and UID filtering
  - Keylog format validation (CLIENT_RANDOM)
  - Integration with tcpdump

**GoTLS Module Advanced Tests**:
- `gotls_advanced_test.sh` - 7 tests
  - Text, pcap, and keylog modes
  - Go client-server communication
  - Multiple concurrent connections
  - Static vs dynamic linking (CGO_ENABLED=0)
  - Debug mode

**Bash Module Advanced Tests**:
- `bash_advanced_test.sh` - 8 tests
  - Pipe commands (`|`)
  - Redirect commands (`>`, `>>`)
  - Background tasks (`&`)
  - Sub-shells (`()`, `$()`)
  - Long command lines
  - Special characters handling
  - Error code filtering (-e parameter)
  - Interactive session simulation

**MySQL Module Advanced Tests**:
- `mysql_advanced_test.sh` - 7 tests
  - SELECT queries
  - INSERT operations
  - UPDATE operations
  - DELETE operations
  - Transaction handling (BEGIN/COMMIT)
  - Long SQL statements
  - Concurrent queries

**Edge Cases and Error Handling**:
- `edge_cases_test.sh` - 15 tests
  - Non-existent PID/UID
  - Invalid library paths
  - Invalid network interface
  - Invalid pcap filter expressions
  - Signal handling (SIGINT, SIGTERM)
  - Read-only output locations
  - Invalid BTF mode
  - Extremely large mapsize
  - Non-existent GoTLS binary
  - MySQL with no server
  - Zero truncation size
  - Negative PID value
  - Empty pcap filename

## Running Tests

### Run All Tests
```bash
# Run all basic + advanced tests (requires root)
sudo make e2e
```

### Run Basic Tests Only
```bash
# Run all basic tests
sudo make e2e-basic

# Run specific basic module tests
sudo make e2e-bash
sudo make e2e-zsh
sudo make e2e-mysql
sudo make e2e-postgres
sudo make e2e-tls
sudo make e2e-gnutls
sudo make e2e-gotls
```

### Run Advanced Tests Only
```bash
# Run all advanced tests
sudo make e2e-advanced

# Run specific advanced tests
sudo make e2e-tls-text-advanced
sudo make e2e-tls-pcap-advanced
sudo make e2e-tls-keylog-advanced
sudo make e2e-gotls-advanced
sudo make e2e-bash-advanced
sudo make e2e-mysql-advanced
sudo make e2e-edge-cases
```

### Run Individual Test Scripts
```bash
# Direct execution
sudo bash ./test/e2e/tls_text_advanced_test.sh
sudo bash ./test/e2e/gotls_advanced_test.sh
# ... etc
```

## Test Output

### Success Indicators
- ✓ Green checkmarks indicate passed tests
- Tests verify:
  - Process starts successfully
  - Captures expected data patterns
  - Output files created (pcap/keylog)
  - Format validation (magic bytes, CLIENT_RANDOM, etc.)

### Warning Indicators  
- ⚠ Yellow warnings indicate:
  - Test completed but with limited verification
  - Optional features not available (e.g., tshark)
  - Environment-specific limitations

### Failure Indicators
- ✗ Red X marks indicate test failures
- Common failure reasons:
  - Process died during startup
  - No output captured
  - Expected patterns not found

### Test Logs
- Temporary output: `/tmp/ecapture_<module>_<test>_<pid>/output/`
- Logs are preserved on test failure for debugging
- Logs are cleaned up automatically on success

## Test Coverage

### Module Coverage
| Module | Basic Tests | Advanced Tests | Total Scenarios |
|--------|-------------|----------------|-----------------|
| TLS (OpenSSL/BoringSSL) | 3 modes | 24 scenarios | 27+ |
| GoTLS | 1 basic | 7 scenarios | 8+ |
| Bash | 2 basic | 8 scenarios | 10+ |
| Zsh | 2 basic | - | 2+ |
| MySQL | 1 basic | 7 scenarios | 8+ |
| PostgreSQL | 1 basic | - | 1+ |
| GnuTLS | 1 basic | - | 1+ |
| NSPR/NSS | - | - | 0 |
| Edge Cases | - | 15 scenarios | 15+ |

**Total**: 70+ test scenarios

### Parameter Coverage
The test suite covers the following parameters:

**Global Parameters**:
- `-d, --debug` - Debug logging ✓
- `-p, --pid` - Process ID filtering ✓
- `-u, --uid` - User ID filtering ✓
- `--hex` - Hex output mode ✓
- `--mapsize` - eBPF map size ✓
- `-t, --tsize` - Text truncation size ✓

**TLS Module Parameters**:
- `-m, --model` - Capture mode (text/pcap/pcapng/key/keylog) ✓
- `-w, --pcapfile` - Pcap output file ✓
- `-k, --keylogfile` - Keylog output file ✓
- `-i, --ifname` - Network interface ✓
- `--libssl` - Custom libssl path ✓ (edge cases)
- Pcap filter expressions ✓

**GoTLS Module Parameters**:
- `-e, --elfpath` - Go binary path ✓
- `-m, --model` - Capture mode ✓
- `-w, --pcapfile` - Pcap output file ✓
- `-k, --keylogfile` - Keylog output file ✓

**Bash/Zsh Module Parameters**:
- `-e, --errnumber` - Error code filtering ✓
- `--bash` - Custom bash path (edge cases)
- `--zsh` - Custom zsh path (edge cases)

**MySQL/Postgres Module Parameters**:
- `--pid` - Database server PID ✓
- `-m, --mysqld` - MySQL binary path
- `-m, --postgres` - Postgres binary path

## Common Testing Patterns

### Pattern 1: Basic Capture Test
```bash
# Start ecapture
ecapture <module> -m text > output.log 2>&1 &
sleep 3

# Generate traffic
curl https://example.com

# Stop ecapture
kill -INT $pid
sleep 2

# Verify output
grep -q "HTTP" output.log
```

### Pattern 2: Parameter Validation
```bash
# Test with invalid parameter
timeout 5 ecapture <module> --invalid-param > output.log 2>&1

# Verify error message
grep -qi "error" output.log
```

### Pattern 3: Signal Handling
```bash
# Start ecapture
ecapture <module> > output.log 2>&1 &
pid=$!

# Send signal
kill -INT $pid
sleep 2

# Verify graceful shutdown
! kill -0 $pid 2>/dev/null
```

## Troubleshooting

### Test Failures

**"Root privileges required"**
- Solution: Run tests with `sudo`

**"Kernel version check failed"**
- Solution: Upgrade kernel to ≥ 4.18 (x86_64) or ≥ 5.5 (aarch64)

**"eCapture binary not found"**
- Solution: Run `make all` or `make nocore` first

**"MySQL/PostgreSQL not available"**
- Solution: Install and start database server, or skip database tests

**"No output captured"**
- Possible reasons:
  - Process completed too quickly (use longer sleep)
  - No matching traffic generated
  - Permissions issue
  - eBPF program failed to attach

### Debug Mode

Run tests with debug logging:
```bash
# Set debug flag in ecapture
ecapture <module> -d > debug.log 2>&1
```

Review debug logs to understand:
- eBPF program attachment status
- Hook function locations
- Event capture details
- Error messages

## Continuous Integration

The test suite is designed to be CI-friendly:

### CI Considerations
- Tests require privileged containers or VMs
- Some tests may need specific kernel versions
- Database tests require running services
- Network tests may be affected by firewall rules

### CI Configuration Example
```yaml
# Example GitHub Actions workflow
jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm golang
      
      - name: Build ecapture
        run: make nocore
      
      - name: Run basic e2e tests
        run: sudo make e2e-basic
```

## Contributing New Tests

### Test File Template
```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/common.sh"

# Configuration
TEST_NAME="My New Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_mytest_$$"

# Cleanup
cleanup_handler() {
    kill_by_pattern "$ECAPTURE_BINARY" || true
    rm -rf "$TMP_DIR"
}
setup_cleanup_trap

# Tests
test_something() {
    log_info "=== Test: Something ==="
    # Test implementation
}

# Main
main() {
    check_root || exit 1
    check_kernel_version 4 18 || exit 1
    mkdir -p "$TMP_DIR"
    build_ecapture "$ECAPTURE_BINARY" || exit 1
    
    test_something || true
    
    log_success "✓ All tests PASSED"
}

main
```

### Adding to Makefile
```makefile
.PHONY: e2e-mytest
e2e-mytest:
	bash ./test/e2e/my_new_test.sh
```

### Test Guidelines
1. Use `common.sh` utilities for consistency
2. Always implement cleanup handlers
3. Make scripts executable: `chmod +x test.sh`
4. Use descriptive test names
5. Log test progress clearly
6. Verify both success and failure cases
7. Clean up on success, preserve on failure
8. Use appropriate timeouts
9. Handle missing dependencies gracefully
10. Document any special requirements

## Test Maintenance

### Regular Updates Needed
- Update tests when adding new CLI parameters
- Add tests for new OpenSSL/library versions
- Update kernel version checks as needed
- Refresh external URLs if they change
- Update expected output patterns

### Version Compatibility
- Tests are designed for current eCapture version
- Some tests may need adjustments for older versions
- Check git tags for version-specific tests

## Future Test Additions

### Planned Tests
- [ ] NSPR/NSS module comprehensive tests
- [ ] GnuTLS advanced scenarios
- [ ] PostgreSQL advanced tests (transactions, procedures)
- [ ] Zsh advanced tests
- [ ] Performance benchmarks
- [ ] Long-running stability tests
- [ ] BTF mode variations (-b 0/1/2)
- [ ] Log forwarding tests (-l parameter)
- [ ] Event collection tests (--eventaddr)
- [ ] HTTP config update tests (--listen)
- [ ] File rotation tests
- [ ] Resource usage validation
- [ ] Multi-process capture coordination

## Support

For issues or questions:
- Check existing test logs in `/tmp/ecapture_*`
- Review this documentation
- Check project README and CONTRIBUTING.md
- Open an issue on GitHub with:
  - Kernel version (`uname -r`)
  - Test output/logs
  - System information
  - Steps to reproduce

## License

Tests are part of the eCapture project and follow the same license (Apache 2.0).
