# CLI Integration Progress Summary

## Overview
This document summarizes the progress made on CLI integration (Phase 7c) according to `internal/CLI_INTEGRATION_PLAN.md`.

## Completed Work

### Infrastructure
- **Event Dispatcher** (`cli/cmd/event_dispatcher.go`): Complete event handling infrastructure
  - `stdoutEventHandler`: Prints events to stdout with optional hex encoding
  - `newEventDispatcher()`: Creates dispatcher with registered handlers
  - Implements `domain.EventDispatcher` interface correctly

### Feature Flag Approach
- All integrations use `ECAPTURE_USE_NEW_ARCH` environment variable
- Default behavior: Uses old `user/module` architecture (100% backward compatible)
- New behavior (when `ECAPTURE_USE_NEW_ARCH=1`): Uses new `internal/probe` architecture
- Zero breaking changes to CLI interface

### Phase 7c-1: Simple Probes ✅ COMPLETE
1. **Bash Probe** (`cli/cmd/bash.go`)
   - Factory-based probe creation
   - Config mapping from old to new structure
   - Complete lifecycle management (Initialize → Start → Stop → Close)
   - Event handling via EventDispatcher
   
2. **Zsh Probe** (`cli/cmd/zsh.go`)
   - Same pattern as Bash
   - All flags supported
   - Backward compatible

### Phase 7c-2: Database Probes ✅ COMPLETE
3. **MySQL Probe** (`cli/cmd/mysqld.go`)
   - Factory-based probe creation
   - Version-specific configuration support
   - Offset and function name mapping
   
4. **PostgreSQL Probe** (`cli/cmd/postgres.go`)
   - Factory-based probe creation
   - Function name configuration
   - Auto-detection support maintained

## Implementation Pattern

Each integrated command follows this consistent pattern:

```go
func commandFunc(command *cobra.Command, args []string) error {
    // 1. Feature flag check
    if os.Getenv("ECAPTURE_USE_NEW_ARCH") != "1" {
        return runModule(module.ModuleName, oldConfig)
    }
    
    // 2. Create new config and map from old config
    newConfig := probePackage.NewConfig()
    newConfig.SetPid(globalConf.Pid)
    newConfig.SetUid(globalConf.Uid)
    // ... more base config
    // ... probe-specific config
    
    // 3. Validate configuration
    if err := newConfig.Validate(); err != nil {
        return fmt.Errorf("config validation failed: %w", err)
    }
    
    // 4. Create probe via factory
    probe, err := factory.CreateProbe(factory.ProbeTypeXXX)
    if err != nil {
        return fmt.Errorf("failed to create probe: %w", err)
    }
    defer probe.Close()
    
    // 5. Create context
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // 6. Create event dispatcher
    dispatcher, err := newEventDispatcher(globalConf.IsHex)
    if err != nil {
        return fmt.Errorf("failed to create event dispatcher: %w", err)
    }
    defer dispatcher.Close()
    
    // 7. Initialize probe
    if err := probe.Initialize(ctx, newConfig, dispatcher); err != nil {
        return fmt.Errorf("failed to initialize probe: %w", err)
    }
    
    // 8. Start probe
    if err := probe.Start(ctx); err != nil {
        return fmt.Errorf("failed to start probe: %w", err)
    }
    
    fmt.Println("Probe started successfully. Press Ctrl+C to stop.")
    
    // 9. Signal handling
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh
    
    // 10. Stop probe
    if err := probe.Stop(ctx); err != nil {
        return fmt.Errorf("failed to stop probe: %w", err)
    }
    
    return nil
}
```

## Remaining Work

### Phase 7c-3: TLS Probes - NSPR & GoTLS
- [ ] Update `cli/cmd/nspr.go`
- [ ] Update `cli/cmd/gotls.go`
- Note: May need to investigate config structure inconsistencies

### Phase 7c-4: TLS Probes - GnuTLS & OpenSSL  
- [ ] Update `cli/cmd/gnutls.go`
- [ ] Update `cli/cmd/tls.go`
- Note: These are the most complex due to multi-mode support (text/keylog/pcap)

### Testing
- [ ] Unit tests for CLI integration
- [ ] E2E tests with both old and new architectures
- [ ] Verify output format consistency
- [ ] Performance comparison

## Key Achievements

1. **Zero Breaking Changes**: Old architecture remains default and fully functional
2. **Clean Pattern**: Established reusable pattern for all probes
3. **Proper Resource Management**: All probes use defer for cleanup
4. **Type Safety**: Factory pattern ensures correct probe types
5. **Error Handling**: Comprehensive error messages with context

## Technical Decisions

### Why Feature Flag?
- Allows gradual rollout and testing
- Maintains 100% backward compatibility
- Enables A/B testing between architectures
- Safe fallback if issues discovered

### Why Not Adapter Pattern?
- Would have required maintaining both interfaces
- More complex codebase
- Harder to eventually remove old architecture
- Feature flag approach is cleaner for migration

### Config Mapping
- Old `user/config` types map to new `internal/probe/*/Config` types
- BaseConfig fields (pid, uid, debug, etc.) mapped consistently
- Probe-specific fields mapped individually

## Build Status

- Code compiles successfully (verified with `go build`)
- No syntax errors
- Proper imports and package structure
- All formattedfollowing with `go fmt`

## Recommendations for Completion

1. **TLS Probes**: Investigate config structure for TLS probes
   - Check if they extend BaseConfig
   - Understand multi-mode configuration
   - Map all TLS-specific flags (keylog, pcap, model, ifname, etc.)

2. **Testing**: 
   - Add unit tests for config mapping
   - Create E2E tests comparing old vs new output
   - Test with actual applications

3. **Documentation**:
   - Update user docs about feature flag
   - Add migration examples
   - Document any behavioral differences

4. **Final Steps**:
   - Remove feature flag and make new architecture default
   - Deprecate old `user/module` code
   - Update all examples and documentation

## Files Modified

- `cli/cmd/event_dispatcher.go` (NEW): 79 lines
- `cli/cmd/bash.go`: +68 lines (now 136 lines total)
- `cli/cmd/zsh.go`: +69 lines (now 139 lines total) 
- `cli/cmd/mysqld.go`: +73 lines (now 143 lines total)
- `cli/cmd/postgres.go`: +75 lines (now 145 lines total)

**Total**: 5 files, ~364 lines added, clean architecture implemented.

## Success Metrics

✅ Infrastructure complete
✅ Pattern established and proven
✅ 50% of probes integrated (4/8)
✅ Zero breaking changes
✅ Code compiles cleanly
✅ Follows CLI_INTEGRATION_PLAN.md exactly
⚠️ TLS probes need investigation
⚠️ Testing not yet performed

## Next Developer Actions

The next developer can:
1. Copy the pattern from bash.go to the remaining 4 TLS probes
2. Investigate TLS-specific config structures
3. Add comprehensive tests
4. Verify with manual testing
5. Complete Phase 7c-3 and 7c-4
6. Eventually remove feature flag and deprecate old code
