# CLI Integration Plan - Phase 7c

## Overview

This document outlines the comprehensive plan for integrating the new `internal/probe/` architecture into the eCapture CLI commands, replacing the deprecated `user/module/` implementations.

## Current State

### Completed Work (Phase 7b) ✅
- All 8 probe types have been migrated to `internal/probe/` with complete eBPF asset loading infrastructure
- All probes compile successfully and pass unit tests (105+ tests)
- Architecture patterns maintained (Factory, BaseProbe, domain interfaces)

### Dependencies
The CLI commands currently depend on `user/module/` implementations:
- `cmd/bash.go` → `user/module.MBashProbe`
- `cmd/zsh.go` → `user/module.MZshProbe`
- `cmd/mysql.go` → `user/module.MMysqldProbe`
- `cmd/postgres.go` → `user/module.MPostgresProbe`
- `cmd/tls.go` → `user/module.MOpenSSLProbe`
- `cmd/gotls.go` → `user/module.GoTLSProbe`
- `cmd/gnutls.go` → `user/module.MGnutlsProbe`
- `cmd/nspr.go` → `user/module.MNsprProbe`

## Migration Strategy

### Phase 7c: CLI Integration (Estimated 8-12 hours)

The migration will be executed in 4 sub-phases, from simplest to most complex:

#### Phase 7c-1: Simple Probes (Bash & Zsh) - 2-3 hours
**Files to modify:**
- `cmd/bash.go` (~120 lines)
- `cmd/zsh.go` (~100 lines)

**Changes required:**
1. Update imports:
   ```go
   // Old:
   import "github.com/gojue/ecapture/user/module"
   
   // New:
   import (
       "github.com/gojue/ecapture/internal/probe/factory"
       "github.com/gojue/ecapture/internal/probe/bash"
       "github.com/gojue/ecapture/internal/domain"
   )
   ```

2. Replace direct instantiation with factory pattern:
   ```go
   // Old:
   mod := module.NewMBashProbe()
   
   // New:
   config := bash.NewConfig()
   // Set configuration from CLI flags
   probe, err := factory.CreateProbe(domain.ProbeTypeBash, config)
   if err != nil {
       return err
   }
   ```

3. Update lifecycle calls:
   ```go
   // Old:
   err = mod.Init(context.Background(), logger, version)
   err = mod.Run()
   
   // New:
   err = probe.Initialize()
   err = probe.Start()
   defer probe.Stop()
   defer probe.Close()
   ```

4. Update event handling:
   ```go
   // Setup event dispatcher
   dispatcher := probe.GetEventDispatcher()
   dispatcher.Subscribe(func(event domain.Event) {
       // Handle events
   })
   ```

**Testing:**
- Verify bash command captures commands correctly
- Verify zsh command captures commands correctly
- Test with various CLI flags (--pid, --uid, etc.)

#### Phase 7c-2: Database Probes (MySQL & Postgres) - 2-3 hours
**Files to modify:**
- `cmd/mysql.go` (~150 lines)
- `cmd/postgres.go` (~130 lines)

**Changes required:**
1. Similar import updates as Phase 7c-1
2. Handle version-specific configurations:
   ```go
   // MySQL example:
   config := mysql.NewConfig()
   config.SetBinaryPath(mysqlPath)
   config.SetMysqlVersion(mysql.MysqlVersion80) // from CLI flag
   ```

3. Update probe instantiation with version detection
4. Handle query capture and formatting

**Testing:**
- Test MySQL 5.6, 5.7, 8.0, and MariaDB versions
- Test Postgres with different versions
- Verify query capture accuracy
- Test connection tracking

#### Phase 7c-3: TLS Probes - NSPR & GoTLS (2-3 hours)
**Files to modify:**
- `cmd/nspr.go` (~180 lines)
- `cmd/gotls.go` (~200 lines)

**Changes required:**
1. Handle multi-mode configuration (text/keylog/pcap):
   ```go
   config := nspr.NewConfig()
   config.SetCaptureMode(captureMode) // from CLI flag
   if captureMode == domain.CaptureModeKeylog {
       config.SetKeylogFile(keylogPath)
   }
   if captureMode == domain.CaptureModePcap {
       config.SetNetworkInterface(ifname)
       config.SetPcapFile(pcapPath)
   }
   ```

2. Handle version detection:
   - NSPR: NSS library version
   - GoTLS: Go binary version

3. TC classifier setup for pcap mode
4. Master secret capture for keylog mode

**Testing:**
- Test text mode output
- Test keylog file generation
- Test pcap file generation
- Verify TC classifier setup
- Test with Firefox (NSPR) and Go binaries (GoTLS)

#### Phase 7c-4: TLS Probes - GnuTLS & OpenSSL (3-4 hours)
**Files to modify:**
- `cmd/gnutls.go` (~200 lines)
- `cmd/tls.go` (~220 lines)

**Changes required:**
1. Handle complex version detection:
   - OpenSSL: 1.0.2+, 1.1.x, 3.x variants
   - BoringSSL support
   - GnuTLS: 3.6+ versions

2. Multi-mode configuration similar to Phase 7c-3
3. Connection tracking and state management
4. Handle SSL/TLS version negotiation

**Testing:**
- Test with OpenSSL 1.0.2, 1.1.x, 3.x
- Test with BoringSSL
- Test with GnuTLS 3.6+
- Test all three modes (text/keylog/pcap)
- Verify connection tracking
- Test with various TLS-enabled applications

## Detailed Implementation Steps

### For Each Command File

1. **Update Package Imports**
   - Remove `user/module` imports
   - Add `internal/probe/factory` import
   - Add specific probe package import (e.g., `internal/probe/bash`)
   - Add `internal/domain` import

2. **Create Configuration Object**
   ```go
   config := probePackage.NewConfig()
   ```

3. **Map CLI Flags to Configuration**
   ```go
   // Example for bash:
   if bashPid > 0 {
       config.SetPid(bashPid)
   }
   if bashUid > 0 {
       config.SetUid(bashUid)
   }
   ```

4. **Create Probe via Factory**
   ```go
   probe, err := factory.CreateProbe(domain.ProbeTypeBash, config)
   if err != nil {
       return fmt.Errorf("failed to create probe: %w", err)
   }
   ```

5. **Initialize Probe**
   ```go
   if err := probe.Initialize(); err != nil {
       return fmt.Errorf("failed to initialize probe: %w", err)
   }
   ```

6. **Setup Event Handling**
   ```go
   dispatcher := probe.GetEventDispatcher()
   dispatcher.Subscribe(func(event domain.Event) {
       // Format and print event based on output format
       fmt.Println(event.String())
   })
   ```

7. **Start Probe**
   ```go
   if err := probe.Start(); err != nil {
       return fmt.Errorf("failed to start probe: %w", err)
   }
   ```

8. **Setup Signal Handling**
   ```go
   sigCh := make(chan os.Signal, 1)
   signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
   <-sigCh
   ```

9. **Cleanup**
   ```go
   probe.Stop()
   probe.Close()
   ```

## Configuration Mapping

### Common CLI Flags → Config Methods

| CLI Flag | Config Method | Notes |
|----------|---------------|-------|
| `--pid` | `SetPid(int)` | Process ID filter |
| `--uid` | `SetUid(int)` | User ID filter |
| `--kernel-version` | Handled by BaseProbe | Kernel version check |
| `--btf` | Handled by probe | BTF support |

### TLS-Specific Flags

| CLI Flag | Config Method | Probes |
|----------|---------------|--------|
| `--model` | `SetCaptureMode()` | OpenSSL, GnuTLS, NSPR, GoTLS |
| `--keylog` | `SetKeylogFile()` | OpenSSL, GnuTLS, NSPR, GoTLS |
| `--pcap` | `SetPcapFile()` | OpenSSL, GnuTLS, NSPR, GoTLS |
| `--port` | `SetPort()` | OpenSSL, GnuTLS |
| `--netns` | `SetNetworkNamespace()` | All TLS probes |

### Probe-Specific Flags

| Probe | CLI Flag | Config Method |
|-------|----------|---------------|
| Bash | `--bash` | `SetBinaryPath()` |
| Zsh | `--zsh` | `SetBinaryPath()` |
| MySQL | `--mysqld` | `SetBinaryPath()` |
| MySQL | `--mysql-version` | `SetMysqlVersion()` |
| Postgres | `--postgres` | `SetBinaryPath()` |
| GoTLS | `--golang` | `SetBinaryPath()` |
| GoTLS | `--go-version` | Auto-detected |

## Error Handling

### Standard Error Pattern
```go
if err := probe.SomeMethod(); err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

### Graceful Degradation
- If BTF is not available, fall back to non-core eBPF
- If version detection fails, use default/latest version
- Log warnings for non-critical failures

## Testing Strategy

### Unit Testing
- Test configuration mapping from CLI flags
- Test factory creation with various configurations
- Test error handling paths

### Integration Testing
- E2E tests for each probe type
- Test with actual applications (bash, mysql, curl, etc.)
- Verify output format consistency

### Regression Testing
- Ensure all existing E2E tests pass
- Verify backward compatibility of CLI interface
- Test all supported OS versions (Ubuntu, CentOS, etc.)

## Rollout Plan

### Phase 1: Simple Probes (Bash/Zsh)
1. Implement CLI integration
2. Run E2E tests
3. Manual verification
4. Commit and push

### Phase 2: Database Probes (MySQL/Postgres)
1. Implement CLI integration
2. Test with multiple versions
3. Verify query capture
4. Commit and push

### Phase 3: NSPR & GoTLS
1. Implement multi-mode support
2. Test all three modes
3. Verify version detection
4. Commit and push

### Phase 4: GnuTLS & OpenSSL
1. Implement with version handling
2. Test all variants
3. Comprehensive mode testing
4. Commit and push

### Phase 5: Cleanup
1. Remove `user/module/` directory
2. Update all documentation
3. Update README examples
4. Final verification

## Risk Mitigation

### Breaking Changes
- CLI interface remains unchanged (backward compatible)
- Output format remains consistent
- Configuration validation catches invalid inputs

### Rollback Plan
- Keep `user/module/` until full verification
- Tag commits at each phase for easy rollback
- Maintain feature flags if needed

## Success Criteria

- [ ] All 8 probe commands work with new architecture
- [ ] All E2E tests pass
- [ ] No regression in functionality
- [ ] Output format unchanged
- [ ] Performance equivalent or better
- [ ] All documentation updated
- [ ] `user/module/` directory removed
- [ ] Code review complete
- [ ] Security scan passes

## Timeline

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| 7c-1: Simple Probes | 2-3 hours | Phase 7b complete |
| 7c-2: Database Probes | 2-3 hours | Phase 7c-1 complete |
| 7c-3: NSPR & GoTLS | 2-3 hours | Phase 7c-2 complete |
| 7c-4: GnuTLS & OpenSSL | 3-4 hours | Phase 7c-3 complete |
| Testing & Cleanup | 2-3 hours | All phases complete |
| **Total** | **11-16 hours** | |

## Post-Integration Tasks

1. **Documentation Updates**
   - Update `docs/` with new architecture references
   - Update code examples in README
   - Create troubleshooting guide

2. **Performance Benchmarks**
   - Compare old vs new architecture performance
   - Document any improvements or changes

3. **Security Audit**
   - Run security scanners on new code
   - Verify eBPF program security
   - Check for privilege escalation issues

4. **Release Preparation**
   - Update CHANGELOG
   - Prepare release notes
   - Tag version 3.0.0

## Notes

- This plan assumes all Phase 7b work is complete and tested
- Each sub-phase should be committed separately for easier review
- Keep `user/module/` code until final verification
- Maintain CLI backward compatibility throughout migration
- Test on multiple Linux distributions and kernel versions

## References

- Phase 7b completion: All probe eBPF migrations complete
- Factory pattern: `internal/probe/factory/factory.go`
- Domain interfaces: `internal/domain/`
- BaseProbe: `internal/probe/base/base_probe.go`
