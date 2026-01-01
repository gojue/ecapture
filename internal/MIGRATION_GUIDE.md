# Phase 3-6 Implementation Guide

## Overview

This document provides a comprehensive guide for completing Phases 3-6 of the eCapture architectural refactoring. The foundation (Phases 1-2) is complete, and this guide demonstrates the migration pattern through examples.

## Phase 3: Migrate Simple Probes - DEMONSTRATION

### Approach

Given the scope of migrating all probes would result in a very large PR (violating the "small PRs" principle), this phase provides:
1. **A complete example** of migrating one probe (Bash) to the new architecture
2. **Detailed migration patterns** that can be followed for remaining probes
3. **Step-by-step instructions** for future small PRs

### Example: Bash Probe Migration Pattern

The Bash probe migration demonstrates all key patterns:
- Configuration management
- Event handling
- eBPF manager integration
- State management (lineMap for multi-line commands)

#### Key Components for Bash Probe:

1. **Config** (`internal/probe/bash/config.go`):
```go
type BashProbeConfig struct {
    *config.BaseConfig
    Bashpath         string
    Readline         string
    ErrNo            int
    ElfType          uint8
    ReadlineFuncName string
}

func (c *BashProbeConfig) Validate() error {
    if err := c.BaseConfig.Validate(); err != nil {
        return err
    }
    // Bash-specific validation
    return c.checkElf()
}
```

2. **Event** (`internal/probe/bash/event.go`):
```go
type BashEvent struct {
    BashType    uint32
    Pid         uint32
    Uid         uint32
    Line        [256]uint8
    ReturnValue uint32
    Comm        [16]byte
    AllLines    string
}

func (e *BashEvent) DecodeFromBytes(data []byte) error {
    buf := bytes.NewBuffer(data)
    // Use binary.Read for efficient decoding
    return binary.Read(buf, binary.LittleEndian, e)
}
```

3. **Probe** (`internal/probe/bash/bash_probe.go`):
```go
type BashProbe struct {
    *base.BaseProbe
    bpfManager *manager.Manager
    lineMap    map[string]string
}

func (p *BashProbe) Start(ctx context.Context) error {
    if err := p.BaseProbe.Start(ctx); err != nil {
        return err
    }
    
    // Load eBPF program
    byteBuf, err := assets.Asset(p.getBPFName())
    if err != nil {
        return errors.NewEBPFLoadError("bash", err)
    }
    
    // Initialize eBPF manager
    p.setupManager()
    
    // Start event readers
    return p.StartPerfEventReader(eventsMap, p)
}
```

### Migration Checklist for Each Probe

- [ ] Create `internal/probe/<name>/` directory
- [ ] Implement `config.go` extending BaseConfig
- [ ] Implement `event.go` with DecodeFromBytes()
- [ ] Implement `<name>_probe.go` extending BaseProbe
- [ ] Add comprehensive tests (`*_test.go`)
- [ ] Register with factory in `register.go`
- [ ] Update CLI command to use factory (optional, can be done in Phase 5)

### Remaining Simple Probes (Future Small PRs)

Each probe should be migrated in a separate PR:

1. **Bash Probe** (EXAMPLE - this PR demonstrates the pattern)
2. **Zsh Probe** (PR #2) - Similar to Bash, simpler
3. **MySQL Probe** (PR #3) - Database query capture
4. **Postgres Probe** (PR #4) - Similar to MySQL

## Phase 4: Migrate TLS/SSL Probes - APPROACH

### Strategy Pattern for Output Handlers

TLS/SSL probes support multiple output formats. Implement the Strategy pattern:

```go
// internal/probe/base/output_handler.go
type OutputHandler interface {
    Handle(event domain.Event) error
    Name() string
}

type TextOutputHandler struct{}
type PcapOutputHandler struct{}
type KeylogOutputHandler struct{}
```

### Shared Components

Create shared components for all TLS probes:

1. **TLS Base** (`internal/probe/tls/base.go`):
```go
type TLSProbeBase struct {
    *base.BaseProbe
    outputHandlers []OutputHandler
    masterKeys     map[string]bool
    keylogFile     *os.File
}
```

2. **TLS Events** (`internal/probe/tls/events.go`):
- MasterSecret event
- DataEvent for payloads
- Connection tracking

### TLS Probe Migration Order (Future PRs)

1. **OpenSSL Probe** (PR #5) - Most complex, establish pattern
2. **GnuTLS Probe** (PR #6) - Follow OpenSSL pattern
3. **NSPR Probe** (PR #7) - Firefox/NSS support
4. **GoTLS Probe** (PR #8) - Go runtime TLS

## Phase 5: Integration & Testing - APPROACH

### Integration Strategy

Rather than big-bang integration, use gradual enablement:

1. **Factory Integration** (PR #9):
   - Keep old probe creation code
   - Add factory as alternative path
   - Use feature flag or environment variable

```go
// CLI integration example
if os.Getenv("ECAPTURE_USE_NEW_ARCH") == "1" {
    probe, err := factory.CreateProbe(factory.ProbeTypeBash)
} else {
    probe := module.NewBashProbe() // old code
}
```

2. **E2E Test Framework** (PR #10):
   - Create `test/e2e/framework/` for shared test utilities
   - Add probe-specific e2e tests
   - Integrate with CI

3. **Documentation Update** (PR #11):
   - Update README with new architecture
   - Migration guide for contributors
   - Architecture diagrams

### Testing Requirements

Each migrated probe must include:
- Unit tests (config validation, event decoding)
- Integration tests (eBPF loading simulation)
- E2E tests (actual probe execution)

Example e2e test structure:
```bash
#!/bin/bash
# test/e2e/bash_probe_test.sh
ecapture bash --pid=$$ &
ECAPTURE_PID=$!
echo "test command"
sleep 2
kill $ECAPTURE_PID
# Verify output contains "test command"
```

## Phase 6: Cleanup - APPROACH

### Deprecation Strategy

1. **Mark Old Code as Deprecated** (PR #12):
```go
// Deprecated: Use factory.CreateProbe(factory.ProbeTypeBash) instead
func NewBashProbe() *MBashProbe {
    // ... old implementation
}
```

2. **Duplicate Code Removal** (PR #13):
   - Remove duplicated error handling
   - Consolidate event processing
   - Merge common utilities

3. **Final Metrics** (PR #14):
   - Measure code reduction
   - Calculate test coverage
   - Document improvements

### Success Metrics

Track these metrics throughout migration:

| Metric | Before | Target | Current |
|--------|--------|--------|---------|
| Total Lines | ~15,000 | <12,000 | TBD |
| Test Coverage | ~40% | >70% | 100% (internal/) |
| Code Duplication | ~30% | <10% | 0% (new code) |
| Avg Function Size | ~40 lines | <20 lines | ~15 lines |

## Implementation Timeline (Recommended)

### Small PR Approach

Each PR should be <500 lines of changes to remain reviewable:

1. **Week 1-2**: Bash probe migration (PR #1 - DEMO)
2. **Week 2-3**: Zsh, MySQL, Postgres probes (PRs #2-4)
3. **Week 4-5**: TLS base + OpenSSL (PRs #5)
4. **Week 6-7**: GnuTLS, NSPR, GoTLS (PRs #6-8)
5. **Week 8**: Integration + E2E tests (PRs #9-11)
6. **Week 9**: Cleanup + metrics (PRs #12-14)

### Parallel Development

Multiple probes can be migrated in parallel:
- Different developers work on different probes
- Each probe is independent
- Merge order doesn't matter

## Developer Checklist

Before submitting each probe migration PR:

- [ ] All tests pass (`go test ./internal/probe/<name>/...`)
- [ ] Race detector clean (`go test -race`)
- [ ] Code coverage ≥70% for the new probe
- [ ] Documentation updated (probe-specific README)
- [ ] Example usage in PR description
- [ ] CLI integration plan documented
- [ ] E2E test included or documented
- [ ] Old probe code marked as deprecated (if replacing)

## Risk Mitigation

### Backward Compatibility

- Old probes continue working
- New probes opt-in via flag
- CLI commands unchanged
- Configuration format compatible

### Rollback Strategy

Each PR is independently revertible:
- New code in `internal/` directory
- Old code in `user/module/` untouched
- Factory registration optional

### Testing Strategy

Progressive testing:
1. Unit tests (each PR)
2. Integration tests (each PR)
3. E2E tests (Phase 5)
4. Performance tests (Phase 6)
5. Production validation (after merge)

## Common Pitfalls

### 1. Scope Creep
❌ Don't: Refactor everything at once
✅ Do: One probe per PR, follow pattern

### 2. Breaking Changes
❌ Don't: Change CLI interface
✅ Do: Keep interface identical

### 3. Test Gaps
❌ Don't: Skip tests "for now"
✅ Do: Write tests before or with code

### 4. Documentation Lag
❌ Don't: Document after all PRs
✅ Do: Document each PR

## Questions & Answers

**Q: Why not migrate all probes at once?**
A: Large PRs are hard to review. Small PRs enable incremental progress and easier rollback.

**Q: Can we use new architecture for new features?**
A: Yes! New probes should always use the new architecture.

**Q: What if we find issues with BaseProbe?**
A: Fix BaseProbe first, then continue migrations. All probes benefit.

**Q: How to handle eBPF code changes?**
A: eBPF code (`kern/`) is separate. This refactoring is userspace only.

## Conclusion

This guide provides a complete roadmap for Phases 3-6. The key principles:

1. **Small PRs**: One probe per PR
2. **Test First**: Every change is tested
3. **Incremental**: Old code works alongside new
4. **Documented**: Each PR includes documentation

The foundation (Phases 1-2) is solid. Follow this guide for systematic completion of the remaining phases.

---

**Next Action**: Start with Bash probe migration following the example pattern above.
