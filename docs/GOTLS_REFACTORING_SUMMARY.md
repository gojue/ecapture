# GoTLS Probe Refactoring Summary

This document summarizes the refactoring work done on the `internal/probe/gotls` module to align it with the standardized probe architecture pattern.

## What Was Changed

### 1. Configuration (`config.go`)
**Before:**
- Standalone Config struct with its own implementation of domain.Configuration methods
- Duplicated methods like `GetPid()`, `GetUid()`, `GetDebug()`, etc.
- Custom JSON serialization in `Bytes()` method

**After:**
- Config extends `config.BaseConfig` using embedding
- Removed redundant methods (inherited from BaseConfig)
- `Validate()` calls `BaseConfig.Validate()` first, then does probe-specific validation
- Added `IsRegisterABI` field to determine Go ABI (register-based for Go 1.17+)
- `Bytes()` delegates to BaseConfig for proper JSON serialization

### 2. Probe Structure (`gotls_probe.go`)
**Before:**
- No BaseProbe usage
- Manual handler management (textHandler, keylogHandler, pcapHandler)
- Incomplete Initialize and Start methods
- No eBPF manager setup
- Missing EventDecoder interface implementation

**After:**
- Embeds `base.BaseProbe` for common functionality
- Initialized with `base.NewBaseProbe("gotls")` in `NewProbe()`
- Complete `Initialize()` with proper type assertion, logging, and file opening
- Complete `Start()` with eBPF loading, manager setup, and event reader initialization
- Added `setupManager()` to configure eBPF probes and maps
- Added `getManagerOptions()` to configure eBPF options
- Added `openOutputFiles()` helper for file handling
- Implemented `Decode()` and `GetDecoder()` for EventDecoder interface
- Updated `Close()` to properly clean up eBPF manager
- Updated `Events()` to return actual event maps

### 3. Event Structures (`event.go`, `event_masterkey.go`)
**Before:**
- `Decode()` method with generic error handling
- `Encode()` method (not needed)
- Simple `String()` method
- Did not implement full domain.Event interface

**After:**
- Renamed `Decode()` to `DecodeFromBytes()` (domain.Event interface requirement)
- Added proper error wrapping with `errors.NewEventDecodeError()`
- Removed `Encode()` method
- Implemented full domain.Event interface:
  - `DecodeFromBytes()` - deserialize from eBPF data
  - `String()` - human-readable format
  - `StringHex()` - hex format
  - `Clone()` - create new instance
  - `Type()` - return EventTypeOutput or EventTypeModuleData
  - `UUID()` - unique identifier
  - `Validate()` - validation logic
- Added `commToString()` helper function
- Fixed field alignment to match eBPF struct (added Comm field to TLSDataEvent)

### 4. Tests (`gotls_probe_test.go`)
**Before:**
- Tests checked for handler fields (textHandler, keylogHandler, pcapHandler)
- `Initialize()` called with nil dispatcher

**After:**
- Created `mockDispatcher` implementing domain.EventDispatcher
- Updated all tests to use proper dispatcher
- Removed checks for handler fields
- Added checks for config and file handles
- All tests passing including race detector

## Key Improvements

### Architecture
✅ Follows standardized probe pattern
✅ Uses BaseProbe for common functionality
✅ Uses BaseConfig for common configuration
✅ Implements all required domain interfaces
✅ Proper separation of concerns

### Code Quality
✅ Proper error handling with domain-specific error types
✅ Structured logging with probe context
✅ Clean resource management
✅ Type-safe configuration handling
✅ No code duplication

### Testing
✅ All unit tests passing
✅ Race detector clean
✅ go vet clean
✅ Proper mocking for dependencies

### Maintainability
✅ Clear code structure
✅ Comprehensive documentation
✅ Follows project conventions
✅ Easy to extend

## Files Modified

```
internal/probe/gotls/config.go          - Config refactored to extend BaseConfig
internal/probe/gotls/event.go           - TLSDataEvent implements domain.Event
internal/probe/gotls/event_masterkey.go - MasterSecretEvent implements domain.Event
internal/probe/gotls/gotls_probe.go     - Complete probe implementation
internal/probe/gotls/gotls_probe_test.go - Updated tests
docs/REFACTORING_GUIDE.md               - Comprehensive refactoring guide (NEW)
```

## eBPF Integration

The refactored probe properly integrates with eBPF:

### Probe Attachment
- **Write probe**: Hooks `crypto/tls.(*Conn).writeRecordLocked`
- **Read probe**: Hooks `crypto/tls.(*Conn).Read`
- **Master secret probe**: Hooks `crypto/tls.(*Config).writeKeyLog` (keylog mode only)

### ABI Handling
- Detects Go version and determines ABI (register-based for Go 1.17+)
- Uses appropriate uprobe section:
  - `uprobe/gotls_write_register` or `uprobe/gotls_write_stack`
  - `uprobe/gotls_read_register` or `uprobe/gotls_read_stack`
  - `uprobe/gotls_mastersecret_register` or `uprobe/gotls_mastersecret_stack`

### Event Maps
- `events` - TLS data read/write events
- `mastersecret_go_events` - TLS master secret events (keylog mode)

## Testing Results

```bash
$ go test -v ./internal/probe/gotls/...
=== RUN   TestNewConfig
--- PASS: TestNewConfig (0.00s)
=== RUN   TestConfig_Validate_GoVersion
--- PASS: TestConfig_Validate_GoVersion (0.00s)
[... 11 more tests ...]
PASS
ok      github.com/gojue/ecapture/internal/probe/gotls  0.006s

$ go test -race -v ./internal/probe/gotls/...
[... all tests pass ...]
PASS
ok      github.com/gojue/ecapture/internal/probe/gotls  1.016s

$ go vet ./internal/probe/gotls/...
[no issues]

$ make format
->  Formatting code
[completed successfully]
```

## Migration Path for Other Probes

This refactoring establishes the pattern for refactoring other probe modules:

1. **openssl** - Similar to gotls, needs BaseProbe/BaseConfig integration
2. **gnutls** - Similar to gotls, needs BaseProbe/BaseConfig integration
3. **mysql** - Follows same pattern
4. **postgres** - Follows same pattern
5. **nspr** - Follows same pattern
6. **zsh** - Similar to bash, should be straightforward

Each probe should follow the detailed steps in `docs/REFACTORING_GUIDE.md`.

## Benefits for Future Development

### For Developers
- Clear, consistent codebase structure
- Easy to understand probe lifecycle
- Reusable components (BaseProbe, BaseConfig)
- Less boilerplate code

### For Maintainers
- Easier code review
- Consistent error handling
- Better logging
- Simpler debugging

### For Contributors
- Clear pattern to follow
- Comprehensive documentation
- Working examples (bash, gotls)
- Detailed refactoring guide

## Next Steps

1. **Review and merge** this PR after validation
2. **Apply pattern** to other probe modules
3. **Update CLI** integration if needed
4. **Add e2e tests** once probes are refactored
5. **Document** any probe-specific quirks

## References

- **Refactoring Guide**: `docs/REFACTORING_GUIDE.md`
- **Reference Implementation**: `internal/probe/bash/`
- **Updated Implementation**: `internal/probe/gotls/`
- **Domain Interfaces**: `internal/domain/`
- **Base Components**: `internal/probe/base/`, `internal/config/`

## Acknowledgments

This refactoring work establishes a solid foundation for the entire eCapture probe system, making it more maintainable, testable, and extensible for future development.
