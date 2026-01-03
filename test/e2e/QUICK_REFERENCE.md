# eCapture E2E Tests - Quick Reference

## Quick Start

```bash
# Build eCapture
make all      # or: make nocore

# Run all tests (requires root)
sudo make e2e

# Run only basic tests
sudo make e2e-basic

# Run only advanced tests
sudo make e2e-advanced
```

## Test Categories

### Basic Tests (11 scenarios)
```bash
sudo make e2e-bash          # Bash command capture
sudo make e2e-zsh           # Zsh command capture
sudo make e2e-mysql         # MySQL query capture
sudo make e2e-postgres      # PostgreSQL query capture
sudo make e2e-tls           # TLS text/pcap/keylog modes
sudo make e2e-gnutls        # GnuTLS capture
sudo make e2e-gotls         # GoTLS capture
```

### Advanced Tests (61 scenarios)

#### TLS Module (24 scenarios)
```bash
sudo make e2e-tls-text-advanced     # HTTP/1.1, HTTP/2, PID/UID filter, concurrent, debug, hex
sudo make e2e-tls-pcap-advanced     # Port/host filter, interface, tshark, mapsize
sudo make e2e-tls-keylog-advanced   # TLS 1.2/1.3, format validation, tcpdump integration
```

#### GoTLS Module (7 scenarios)
```bash
sudo make e2e-gotls-advanced        # Text/pcap/keylog modes, client-server, static binary
```

#### Bash Module (8 scenarios)
```bash
sudo make e2e-bash-advanced         # Pipes, redirects, background, subshells, special chars
```

#### MySQL Module (7 scenarios)
```bash
sudo make e2e-mysql-advanced        # SELECT, INSERT, UPDATE, DELETE, transactions, concurrent
```

#### Edge Cases (15 scenarios)
```bash
sudo make e2e-edge-cases            # Invalid inputs, signals, permissions, boundary tests
```

## Test Results Legend

| Symbol | Meaning | Description |
|--------|---------|-------------|
| ✓ | PASS | Test completed successfully with expected results |
| ⚠ | WARN | Test completed but with limited verification or optional features |
| ✗ | FAIL | Test failed - check logs for details |
| ⊘ | SKIP | Test skipped due to missing dependencies |

## Common Issues

### "Root privileges required"
```bash
# Solution: Run with sudo
sudo make e2e-tls
```

### "Kernel version check failed"
```bash
# Check your kernel version
uname -r

# Required: x86_64 >= 4.18 or aarch64 >= 5.5
```

### "eCapture binary not found"
```bash
# Build first
make all         # or make nocore
```

### "MySQL not available"
```bash
# Install MySQL/MariaDB
sudo apt-get install mysql-server mysql-client

# Start service
sudo systemctl start mysql
```

### "Test produced no output"
Possible causes:
- Process completed too quickly (check sleep durations)
- No matching traffic generated
- eBPF program failed to attach (check dmesg)
- Permissions issue

## Debug Mode

```bash
# Run test script directly with bash -x
sudo bash -x ./test/e2e/tls_text_advanced_test.sh

# Check eCapture debug output
sudo ecapture tls -m text -d > debug.log 2>&1
```

## Test Logs Location

```bash
# Temporary test output (preserved on failure)
/tmp/ecapture_<module>_<test>_<pid>/output/

# Example:
/tmp/ecapture_tls_text_advanced_12345/output/
  ├── http11.log
  ├── http2.log
  ├── pid_filter.log
  └── ...
```

## Module-Specific Requirements

### TLS/GoTLS Tests
- **Required**: curl
- **Optional**: tshark (for pcap verification), tcpdump (for keylog integration)

### Bash/Zsh Tests
- **Required**: bash or zsh
- **Note**: bash should be linked with readline for best results

### MySQL Tests
- **Required**: mysql-client, MySQL/MariaDB server running
- **Setup**: Test database is created/cleaned automatically

### PostgreSQL Tests
- **Required**: postgresql-client, PostgreSQL server running
- **Setup**: Test database is created/cleaned automatically

## File Structure

```
test/e2e/
├── common.sh                    # Shared utilities
├── README.md                    # Full documentation
├── QUICK_REFERENCE.md          # This file
├── run_e2e.sh                  # Simple smoke test runner
│
├── *_e2e_test.sh               # Basic tests (7 files)
│   ├── bash_e2e_test.sh
│   ├── zsh_e2e_test.sh
│   ├── mysql_e2e_test.sh
│   ├── postgres_e2e_test.sh
│   ├── tls_e2e_test.sh
│   ├── gnutls_e2e_test.sh
│   └── gotls_e2e_test.sh
│
└── *_advanced_test.sh          # Advanced tests (6 files)
    ├── tls_text_advanced_test.sh
    ├── tls_pcap_advanced_test.sh
    ├── tls_keylog_advanced_test.sh
    ├── gotls_advanced_test.sh
    ├── bash_advanced_test.sh
    ├── mysql_advanced_test.sh
    └── edge_cases_test.sh
```

## Test Execution Time

| Test Category | Approx. Duration | Notes |
|---------------|------------------|-------|
| Basic tests | 2-5 minutes | Depends on network speed |
| TLS advanced | 3-5 minutes | Network-dependent |
| GoTLS advanced | 2-4 minutes | Includes Go compilation |
| Bash advanced | 1-2 minutes | Fast |
| MySQL advanced | 2-3 minutes | Requires MySQL running |
| Edge cases | 1-2 minutes | Fast |
| **Total (all)** | **10-20 minutes** | Full e2e suite |

## Parameter Coverage Checklist

### Tested Parameters ✓
- `-d, --debug` - Debug logging
- `-p, --pid` - Process ID filtering
- `-u, --uid` - User ID filtering
- `-m, --model` - Capture mode (text/pcap/keylog)
- `-w, --pcapfile` - Pcap output file
- `-k, --keylogfile` - Keylog output file
- `-i, --ifname` - Network interface
- `-t, --tsize` - Text truncation size
- `-e, --elfpath` - Go binary path (GoTLS)
- `-e, --errnumber` - Error code filter (Bash/Zsh)
- `--hex` - Hex output mode
- `--mapsize` - eBPF map size
- Pcap filter expressions

### Not Yet Tested (Future Work)
- `-b, --btf` - BTF mode (0/1/2)
- `-l, --logaddr` - Log forwarding
- `--eventaddr` - Event collection
- `--listen` - HTTP config update
- `--eventroratesize` - Event file rotation size
- `--eventroratetime` - Event file rotation time
- `--libssl`, `--gnutls`, `--nspr` - Custom library paths
- `--cgroup_path` - CGroup path
- `--ssl_version` - SSL version string

## CI Integration Example

```yaml
# .github/workflows/e2e-tests.yml
name: E2E Tests

on: [push, pull_request]

jobs:
  basic-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm golang-go curl
      
      - name: Build eCapture
        run: make nocore
      
      - name: Run basic e2e tests
        run: sudo make e2e-basic
      
      - name: Upload test logs on failure
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: test-logs
          path: /tmp/ecapture_*
```

## Manual Test Execution

```bash
# Direct script execution
cd /path/to/ecapture
sudo bash ./test/e2e/tls_text_advanced_test.sh

# With explicit bash debugging
sudo bash -x ./test/e2e/tls_text_advanced_test.sh

# Run specific test from script (edit script to comment out unwanted tests)
sudo bash ./test/e2e/tls_text_advanced_test.sh
```

## Test Output Examples

### Successful Test
```
[INFO] === Test 1: HTTP/1.1 Capture ===
[INFO] Starting ecapture in text mode
[INFO] Making HTTP/1.1 request to https://www.github.com
[SUCCESS] ✓ HTTP/1.1 capture test PASSED
```

### Warning
```
[INFO] === Test 3: PID Filtering ===
[INFO] Starting ecapture with PID filter: 12345
[WARN] ⚠ PID filtering test produced no output (process may have completed too quickly)
```

### Failure
```
[INFO] === Test 5: Concurrent Connections ===
[ERROR] eCapture died during startup
[ERROR] ✗ Concurrent connections test FAILED
```

## Performance Tips

1. **Parallel Testing**: Tests run sequentially by default. For faster results, run different modules in parallel:
   ```bash
   sudo make e2e-tls &
   sudo make e2e-gotls &
   wait
   ```

2. **Skip Optional Tests**: Comment out tests you don't need in the script

3. **Reduce Sleep Times**: For faster iteration during development (may cause false failures)

4. **Use Local Cache**: Pre-download test URLs or use local servers

## Contributing New Tests

See the [full README.md](README.md#contributing-new-tests) for detailed guidelines.

Quick template:
```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="My Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"

cleanup_handler() {
    kill_by_pattern "$ECAPTURE_BINARY" || true
}
setup_cleanup_trap

main() {
    check_root || exit 1
    build_ecapture "$ECAPTURE_BINARY" || exit 1
    
    # Your tests here
    
    log_success "✓ Tests PASSED"
}

main
```

## Support

- **Documentation**: See [test/e2e/README.md](README.md)
- **Issues**: Open on GitHub with test logs
- **Questions**: Check project README and CONTRIBUTING.md

---

**Total Test Coverage**: 72+ scenarios across 8 modules
**Execution Time**: ~10-20 minutes for full suite
**Requirements**: Linux kernel ≥ 4.18, root access
