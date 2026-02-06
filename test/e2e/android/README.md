# eCapture Android E2E Test Suite

This directory contains end-to-end tests for eCapture on Android platforms.

## Overview

The Android E2E test suite validates eCapture's core functionality on Android 15+ devices with ARM64 architecture and kernel 5.5+. Tests cover:

- **TLS Module**: OpenSSL/BoringSSL capture (text & pcap modes)
- **GoTLS Module**: Go TLS client capture (text & keylog modes)
- **Bash Module**: Shell command capture

## Requirements

### System Requirements

#### Android Device/Emulator
- **OS**: Android 15+ (API Level 35+)
- **Architecture**: ARM64 (aarch64)
- **Kernel**: Linux 5.5+
- **Root**: Required for eBPF operations
- **SELinux**: Permissive mode (automatically configured)

#### Development Environment
- **Build System**: Linux (kernel 4.18+)
  - Cannot build Android binaries on macOS
  - Use remote Linux server if needed
- **Tools**:
  - ADB (Android Debug Bridge)
  - Go 1.21+
  - Clang/LLVM 14+
  - Android SDK Platform Tools

### Android Device Options

1. **Android Emulator** (Recommended for CI/CD)
   - Easier to get root access
   - GitHub Actions compatible
   - Configure with ARM64 system image

2. **Physical Device**
   - Better performance
   - Real-world testing
   - Requires rooted device

## Quick Start

### 1. Build for Android (on Linux)

```bash
# On Linux build server
cd /path/to/ecapture
ANDROID=1 make nocore

# Or use the build script
bash test/e2e/android/build_android_tests.sh
```

**From macOS**: Build on remote Linux server

```bash
# Build on remote server
ssh cfc4n@172.16.71.128 'cd /home/cfc4n/project/ecapture && ANDROID=1 make nocore'

# Copy binary back to macOS
scp cfc4n@172.16.71.128:/home/cfc4n/project/ecapture/bin/ecapture bin/
```

### 2. Setup Android Device

```bash
# Connect device via USB or start emulator
adb devices

# Verify connection
bash test/e2e/android/setup_android_env.sh
```

### 3. Run Tests

```bash
# Individual tests
make e2e-android-tls
make e2e-android-gotls
make e2e-android-bash

# All Android tests
make e2e-android-all
```

Or run scripts directly:

```bash
bash test/e2e/android/android_tls_e2e_test.sh
bash test/e2e/android/android_gotls_e2e_test.sh
bash test/e2e/android/android_bash_e2e_test.sh
```

## Test Modules

### TLS Module Tests (`android_tls_e2e_test.sh`)

Tests OpenSSL/BoringSSL TLS capture on Android:

1. **Text Mode**: Captures plaintext HTTP/HTTPS traffic
2. **PCAP Mode**: Captures decrypted packets to pcapng format
3. **PID Filter**: Tests process-specific capture

**Requirements**: `curl` or `wget` on device

### GoTLS Module Tests (`android_gotls_e2e_test.sh`)

Tests Go TLS library capture:

1. **Text Mode**: Captures Go TLS plaintext
2. **Keylog Mode**: Extracts TLS session keys
3. **Concurrent Connections**: Multiple simultaneous captures

**Requirements**: Go test client binary (auto-built)

### Bash Module Tests (`android_bash_e2e_test.sh`)

Tests shell command capture:

1. **Basic Commands**: Captures standard shell commands
2. **Long Commands**: Tests command truncation handling
3. **Pipe Commands**: Tests complex shell pipelines

**Requirements**: Shell (`sh`) on device

## File Structure

```
test/e2e/android/
├── README.md                       # This file
├── common_android.sh               # Common utilities for Android tests
├── android_tls_e2e_test.sh        # TLS module tests
├── android_gotls_e2e_test.sh      # GoTLS module tests
├── android_bash_e2e_test.sh       # Bash module tests
├── build_android_tests.sh         # Build script for Android binaries
├── setup_android_env.sh           # Environment setup and validation
└── go_https_client_android        # Go test client (generated)
```

## Using Android Emulator

### Local Emulator Setup

```bash
# Install Android SDK and emulator
# macOS:
brew install --cask android-commandlinetools

# Create AVD with ARM64 system image
sdkmanager "system-images;android-35;google_apis;arm64-v8a"
avdmanager create avd -n android15_arm64 \
  -k "system-images;android-35;google_apis;arm64-v8a" \
  -d pixel_6_pro

# Start emulator with writable system
emulator -avd android15_arm64 -writable-system -no-snapshot-save &

# Wait for boot
adb wait-for-device

# Get root
adb root
adb wait-for-device

# Set SELinux permissive
adb shell setenforce 0
```

### Emulator in CI/CD

The GitHub Actions workflow (`../.github/workflows/android_e2e.yml`) uses `reactivecircus/android-emulator-runner@v2` action:

- Automatic AVD creation and caching
- Root access enabled
- ARM64 architecture support
- Optimized for CI performance

## Troubleshooting

### Common Issues

#### 1. "No Android device connected"

**Solution**:
```bash
# Check USB connection
adb devices

# Restart ADB server
adb kill-server
adb start-server
adb devices
```

#### 2. "Failed to get root access"

**Solution**:
```bash
# For emulator
adb root

# For physical device
# Device must be rooted (Magisk, SuperSU, etc.)
# Enable root debugging in developer options
```

#### 3. "SELinux is in Enforcing mode"

**Solution**:
```bash
# Set to permissive
adb shell setenforce 0

# Verify
adb shell getenforce
```

#### 4. "Binary is not ARM64"

**Solution**:
```bash
# Must build on Linux with ANDROID=1
ANDROID=1 make nocore

# Verify architecture
file bin/ecapture
# Should show: ARM aarch64
```

#### 5. "curl not found on device"

**Solution**:
- Use a device with curl/wget pre-installed
- Install busybox on device
- Or use a custom ROM with networking tools

#### 6. "Kernel version too old"

**Solution**:
- Use Android 15+ device (kernel 5.5+)
- Check kernel: `adb shell uname -r`
- Upgrade device or use newer emulator image

### Debug Mode

Enable verbose logging:

```bash
# Run tests with debug output
adb shell "$DEVICE_ECAPTURE tls -m text -d" > /tmp/debug.log 2>&1
```

View logs:

```bash
# Pull device logs
adb pull /data/local/tmp/ecapture_test/ecapture.log ./

# View last 100 lines
tail -100 ecapture.log
```

## CI/CD Integration

### GitHub Actions

The workflow is triggered on:
- Push to `master` or `v2` branches
- Pull requests affecting Android code
- Manual workflow dispatch

### Workflow Steps

1. Build ecapture for Android ARM64
2. Build Go test client for Android
3. Create/cache Android emulator AVD
4. Start emulator with root access
5. Run all Android e2e tests
6. Upload test artifacts

### Running Manually

```bash
# Trigger workflow via GitHub UI
# Actions → Android E2E Tests → Run workflow

# Or push to trigger
git push origin feature/android-tests
```

## Performance Considerations

### Test Duration

- TLS test: ~2-3 minutes
- GoTLS test: ~3-4 minutes
- Bash test: ~1-2 minutes
- Total: ~6-9 minutes

### Resource Usage

- Emulator RAM: 4GB
- Emulator disk: 8GB
- CPU: 2+ cores recommended

### Optimization Tips

1. **Use AVD caching** (GitHub Actions)
2. **Disable animations**: Speeds up emulator
3. **Skip snapshots**: Faster startup
4. **Parallel tests**: If multiple devices available

## Contributing

### Adding New Tests

1. Create test script in `test/e2e/android/`
2. Use `common_android.sh` utilities
3. Follow existing test structure:
   - Prerequisites check
   - Setup
   - Test execution
   - Cleanup
   - Summary

Example:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common_android.sh"

# Test implementation
test_my_feature() {
    log_info "Testing my feature..."
    # Test code here
}

main() {
    check_android_prerequisites || exit 1
    test_my_feature
    log_success "Test passed"
}

main
```

4. Add Makefile target:

```makefile
.PHONY: e2e-android-mytest
e2e-android-mytest:
	bash ./test/e2e/android/android_mytest_e2e_test.sh
```

5. Update workflow if needed

### Testing Checklist

- [ ] Test runs on Android 15+ emulator
- [ ] Test handles missing tools gracefully
- [ ] Cleanup removes temporary files
- [ ] Logs are informative
- [ ] Test summary shows pass/fail counts
- [ ] Works with both curl and wget (if applicable)

## Known Limitations

1. **Architecture**: Only ARM64 supported (Android standard)
2. **Android Version**: Requires API 35+ (Android 15+)
3. **Root**: Mandatory for eBPF operations
4. **SELinux**: Must be permissive
5. **Emulator Performance**: Slower than physical device
6. **Tool Availability**: Some devices lack curl/wget
7. **BoringSSL Version**: Auto-detected based on Android API

## Future Enhancements

- [ ] Support for older Android versions (14, 13)
- [ ] NSPR/NSS module tests
- [ ] GnuTLS tests (if available on Android)
- [ ] MySQL/PostgreSQL tests (with server on device)
- [ ] Performance benchmarks
- [ ] Multiple concurrent device testing
- [ ] Real device testing in CI/CD

## Resources

- [Android Debugging Documentation](https://developer.android.com/studio/command-line/adb)
- [Android Emulator Guide](https://developer.android.com/studio/run/emulator)
- [eBPF on Android](https://source.android.com/docs/core/architecture/kernel/bpf)
- [GitHub Actions Android Emulator](https://github.com/ReactiveCircus/android-emulator-runner)

## Support

For issues or questions:

1. Check this README
2. Review test logs in `/tmp/ecapture_android_*`
3. Verify prerequisites with `setup_android_env.sh`
4. Open GitHub issue with:
   - Device info (`adb shell getprop ro.build.version.release`)
   - Kernel version (`adb shell uname -r`)
   - Test output
   - Error logs
