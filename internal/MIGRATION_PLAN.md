# Phase 7b: eBPF Code Migration Plan

## Overview

Migrating eBPF implementation code from `user/module/` to `internal/probe/` to complete the TODO items.

## Source Analysis

**Files to migrate**: 24 files, ~5,750 lines
**Target**: Integrate into corresponding `internal/probe/` implementations

## Migration Strategy

### Probe-by-Probe Approach

For each probe type, migrate in this order (simplest to most complex):

1. **Bash** (user/module/probe_bash.go → internal/probe/bash/)
2. **Zsh** (user/module/probe_zsh.go → internal/probe/zsh/)  
3. **MySQL** (user/module/probe_mysqld.go → internal/probe/mysql/)
4. **Postgres** (user/module/probe_postgres.go → internal/probe/postgres/)
5. **NSPR** (user/module/probe_nspr.go → internal/probe/nspr/)
6. **GoTLS** (user/module/probe_gotls*.go → internal/probe/gotls/)
7. **GnuTLS** (user/module/probe_gnutls*.go → internal/probe/gnutls/)
8. **OpenSSL** (user/module/probe_openssl*.go → internal/probe/openssl/)

### Per-Probe Migration Steps

For each probe:

1. **Extract eBPF manager code**
   - BPF manager initialization
   - Event map setup
   - Hook attachment logic

2. **Extract event handling code**
   - Event reading loops
   - Event decoding
   - Event dispatching

3. **Integrate into new architecture**
   - Add to probe's Start() method
   - Add to probe's Stop() method  
   - Add to probe's Close() method
   - Add to probe's Events() method

4. **Preserve new patterns**
   - Keep handler separation (text/keylog/pcap)
   - Maintain BaseProbe structure
   - Use new error handling

5. **Test compilation**
   - Verify code compiles
   - Check for missing dependencies

## Key Challenges

1. **Import paths**: Update from old to new package structure
2. **Interface compatibility**: Adapt old code to new domain interfaces
3. **State management**: Integrate connection tracking into new probe structure
4. **Error handling**: Convert to new error types

## Implementation Notes

- **Preserve working eBPF C code**: Don't modify kern/*.c files
- **Adapt Go wrapper code**: Integrate eBPF manager calls into new probe lifecycle
- **Maintain handlers**: Keep separation between text/keylog/pcap output modes
- **Test incrementally**: Verify each probe after migration

## Estimated Effort

- Simple probes (Bash, Zsh, MySQL, Postgres): ~1-2 hours each
- Medium probes (NSPR, GoTLS): ~2-3 hours each  
- Complex probes (GnuTLS, OpenSSL): ~3-4 hours each

**Total**: ~16-24 hours of focused development

## Success Criteria

- [ ] All probe types have complete eBPF implementations
- [ ] Code compiles without errors
- [ ] New architecture patterns preserved
- [ ] No functionality regression
- [ ] Ready for CLI integration

## Next Phase

After migration complete:
- Phase 7c: CLI Integration
- Phase 7d: Remove user/module/
- Phase 7e: Final testing and validation
