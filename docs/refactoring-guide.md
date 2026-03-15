# eCapture Probe Refactoring Guide

This guide documents the strategy, patterns, and key considerations for refactoring probe modules in the eCapture project, based on the successful refactoring of the `gotls` probe using `bash` probe as a reference template.

## Table of Contents
1. [Overview](#overview)
2. [Architecture Pattern](#architecture-pattern)
3. [Step-by-Step Refactoring Process](#step-by-step-refactoring-process)
4. [Key Components](#key-components)
5. [Common Pitfalls](#common-pitfalls)
6. [Testing Strategy](#testing-strategy)

## Overview

The refactoring effort aims to standardize probe implementations to follow a consistent architecture using:
- **BaseProbe**: Common probe functionality (lifecycle, logging, event reading)
- **BaseConfig**: Common configuration (BTF mode, PID/UID filtering, debug flags)
- **domain interfaces**: Probe, Event, EventDecoder, EventDispatcher interfaces
- **eBPF Manager**: Standardized eBPF program loading and management

## Architecture Pattern

### Core Interfaces

```go
// domain.Probe - Main probe interface
type Probe interface {
    Initialize(ctx context.Context, config Configuration, dispatcher EventDispatcher) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Close() error
    Name() string
    IsRunning() bool
    Events() []*ebpf.Map
}

// domain.EventDecoder - For decoding eBPF events
type EventDecoder interface {
    Decode(em *ebpf.Map, data []byte) (Event, error)
    GetDecoder(em *ebpf.Map) (Event, bool)
}

// domain.Event - Event structure interface
type Event interface {
    DecodeFromBytes(data []byte) error
    String() string
    StringHex() string
    Clone() Event
    Type() EventType
    UUID() string
    Validate() error
}
```

### Probe Structure Pattern

```go
type Probe struct {
    *base.BaseProbe             // Embed BaseProbe for common functionality
    config     *Config          // Probe-specific configuration
    bpfManager *manager.Manager // eBPF program manager
    eventMaps  []*ebpf.Map      // eBPF event maps
    
    // Probe-specific fields (e.g., file handles, state)
}
```

### Configuration Pattern

```go
type Config struct {
    *config.BaseConfig  // Embed BaseConfig for common settings
    
    // Probe-specific configuration fields
    SpecificField1 string `json:"specific_field1"`
    SpecificField2 bool   `json:"specific_field2"`
}

func (c *Config) Validate() error {
    // Validate BaseConfig first
    if err := c.BaseConfig.Validate(); err != nil {
        return err
    }
    
    // Validate probe-specific fields
    return nil
}
```

## Step-by-Step Refactoring Process

### 1. Update Configuration

**Reference**: `internal/probe/bash/config.go`

1. Extend `config.BaseConfig`:
   ```go
   type Config struct {
       *config.BaseConfig
       // ... probe-specific fields
   }
   ```

2. Update `NewConfig()`:
   ```go
   func NewConfig() *Config {
       return &Config{
           BaseConfig: config.NewBaseConfig(),
           // ... initialize probe-specific defaults
       }
   }
   ```

3. Update `Validate()` method:
   ```go
   func (c *Config) Validate() error {
       if err := c.BaseConfig.Validate(); err != nil {
           return errors.NewConfigurationError("validation failed", err)
       }
       // ... probe-specific validation
       return nil
   }
   ```

4. Remove redundant methods that are now inherited from BaseConfig:
   - `GetPid()`, `GetUid()`, `GetDebug()`, `GetHex()`, `GetBTF()`, etc.
   - These are all provided by BaseConfig

5. Keep probe-specific methods and ensure `Bytes()` delegates to BaseConfig if no special serialization needed.

### 2. Update Probe Structure

**Reference**: `internal/probe/bash/bash_probe.go`

1. Initialize BaseProbe:
   ```go
   func NewProbe() (*Probe, error) {
       return &Probe{
           BaseProbe: base.NewBaseProbe("probename"),
       }, nil
   }
   ```

2. Implement `Initialize()`:
   ```go
   func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, 
                              dispatcher domain.EventDispatcher) error {
       // Call BaseProbe.Initialize first
       if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
           return err
       }
       
       // Type assert to probe-specific config
       probeConfig, ok := cfg.(*Config)
       if !ok {
           return errors.NewConfigurationError("invalid config type", nil)
       }
       p.config = probeConfig
       
       // Log probe initialization with relevant fields
       p.Logger().Info().
           Str("field1", probeConfig.Field1).
           Msg("Probe initialized")
       
       // Probe-specific initialization (open files, etc.)
       return nil
   }
   ```

3. Implement `Start()`:
   ```go
   func (p *Probe) Start(ctx context.Context) error {
       // Call BaseProbe.Start
       if err := p.BaseProbe.Start(ctx); err != nil {
           return err
       }
       
       // Load eBPF bytecode
       bpfFileName := p.BaseProbe.GetBPFName("bytecode/probe_kern.o")
       byteBuf, err := assets.Asset(bpfFileName)
       if err != nil {
           return errors.NewEBPFLoadError(bpfFileName, err)
       }
       
       // Setup and initialize eBPF manager
       if err := p.setupManager(); err != nil {
           return err
       }
       
       if err := p.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), 
                                              p.getManagerOptions()); err != nil {
           return errors.NewEBPFLoadError("manager init", err)
       }
       
       // Start eBPF manager
       if err := p.bpfManager.Start(); err != nil {
           return errors.NewEBPFAttachError("manager start", err)
       }
       
       // Get event maps
       eventsMap, found, err := p.bpfManager.GetMap("events")
       if err != nil || !found {
           return errors.NewResourceNotFoundError("eBPF map: events")
       }
       p.eventMaps = []*ebpf.Map{eventsMap}
       
       // Start event readers
       if err := p.StartPerfEventReader(eventsMap, p); err != nil {
           return err
       }
       
       return nil
   }
   ```

4. Implement `setupManager()`:
   ```go
   func (p *Probe) setupManager() error {
       p.bpfManager = &manager.Manager{
           Probes: []*manager.Probe{
               {
                   Section:          "uprobe/function_name",
                   EbpfFuncName:     "uprobe_function",
                   AttachToFuncName: "target_function",
                   BinaryPath:       p.config.BinaryPath,
               },
               // ... more probes
           },
           Maps: []*manager.Map{
               {Name: "events"},
               // ... more maps
           },
       }
       return nil
   }
   ```

5. Implement `getManagerOptions()`:
   ```go
   func (p *Probe) getManagerOptions() manager.Options {
       opts := manager.Options{
           DefaultKProbeMaxActive: 512,
           VerifierOptions: ebpf.CollectionOptions{
               Programs: ebpf.ProgramOptions{
                   LogSizeStart: 2097152,
               },
           },
           RLimit: &unix.Rlimit{
               Cur: math.MaxUint64,
               Max: math.MaxUint64,
           },
       }
       
       // Add constant editors if kernel supports global variables
       if p.config.EnableGlobalVar() {
           opts.ConstantEditors = []manager.ConstantEditor{
               {Name: "target_pid", Value: p.config.GetPid()},
               {Name: "target_uid", Value: p.config.GetUid()},
           }
       }
       
       return opts
   }
   ```

6. Update `Close()`:
   ```go
   func (p *Probe) Close() error {
       // Stop eBPF manager
       if p.bpfManager != nil {
           if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
               p.Logger().Warn().Err(err).Msg("Failed to stop eBPF manager")
           }
       }
       
       // Clean up probe-specific resources
       
       // Call BaseProbe.Close
       return p.BaseProbe.Close()
   }
   ```

7. Implement `Events()`:
   ```go
   func (p *Probe) Events() []*ebpf.Map {
       return p.eventMaps
   }
   ```

### 3. Update Event Structures

**Reference**: `internal/probe/bash/event.go`

1. Import required packages:
   ```go
   import (
       "github.com/gojue/ecapture/internal/domain"
       "github.com/gojue/ecapture/internal/errors"
   )
   ```

2. Rename `Decode()` to `DecodeFromBytes()`:
   ```go
   func (e *Event) DecodeFromBytes(data []byte) error {
       buf := bytes.NewBuffer(data)
       
       if err := binary.Read(buf, binary.LittleEndian, &e.Field1); err != nil {
           return errors.NewEventDecodeError("Event.Field1", err)
       }
       // ... decode other fields
       
       return nil
   }
   ```

3. Implement domain.Event interface methods:
   ```go
   // String returns a human-readable representation
   func (e *Event) String() string {
       return fmt.Sprintf("Field1:%v, Field2:%v", e.Field1, e.Field2)
   }
   
   // StringHex returns a hexadecimal representation
   func (e *Event) StringHex() string {
       hexData := fmt.Sprintf("%x", e.Data)
       return fmt.Sprintf("Field1:%v, Data(hex):%s", e.Field1, hexData)
   }
   
   // Clone creates a new instance
   func (e *Event) Clone() domain.Event {
       return &Event{}
   }
   
   // Type returns the event type
   func (e *Event) Type() domain.EventType {
       return domain.EventTypeOutput
   }
   
   // UUID returns a unique identifier
   func (e *Event) UUID() string {
       return fmt.Sprintf("%d_%d", e.Pid, e.Timestamp)
   }
   
   // Validate checks if the event data is valid
   func (e *Event) Validate() error {
       // Validation logic
       return nil
   }
   ```

4. Remove `Encode()` method if present (not needed for domain.Event interface)

### 4. Implement EventDecoder Interface

Add these methods to the Probe:

```go
// Decode implements EventDecoder interface
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
    for _, m := range p.eventMaps {
        if m == em {
            event := &Event{}
            if err := event.DecodeFromBytes(data); err != nil {
                return nil, err
            }
            return event, nil
        }
    }
    return nil, fmt.Errorf("unknown eBPF map: %s", em.String())
}

// GetDecoder implements EventDecoder interface
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
    for _, m := range p.eventMaps {
        if m == em {
            return &Event{}, true
        }
    }
    return nil, false
}
```

For probes with multiple event types (like gotls with TLSDataEvent and MasterSecretEvent):

```go
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
    for i, m := range p.eventMaps {
        if m == em {
            if i == 0 {  // First map is data events
                event := &DataEvent{}
                if err := event.DecodeFromBytes(data); err != nil {
                    return nil, err
                }
                return event, nil
            }
            if i == 1 {  // Second map is metadata events
                event := &MetadataEvent{}
                if err := event.DecodeFromBytes(data); err != nil {
                    return nil, err
                }
                return event, nil
            }
        }
    }
    return nil, fmt.Errorf("unknown eBPF map: %s", em.String())
}
```

### 5. Update Tests

**Reference**: `internal/probe/bash/bash_probe_test.go` or updated `internal/probe/gotls/gotls_probe_test.go`

1. Create a mock dispatcher:
   ```go
   type mockDispatcher struct{}
   
   func (m *mockDispatcher) Register(handler domain.EventHandler) error { return nil }
   func (m *mockDispatcher) Unregister(handlerName string) error        { return nil }
   func (m *mockDispatcher) Dispatch(event domain.Event) error          { return nil }
   func (m *mockDispatcher) Close() error                               { return nil }
   ```

2. Update test initialization:
   ```go
   func TestProbe_Initialize(t *testing.T) {
       probe, err := NewProbe()
       if err != nil {
           t.Fatalf("NewProbe() failed: %v", err)
       }
       
       cfg := NewConfig()
       // Set config fields
       
       ctx := context.Background()
       dispatcher := &mockDispatcher{}
       if err := probe.Initialize(ctx, cfg, dispatcher); err != nil {
           t.Errorf("Initialize() failed: %v", err)
       }
       
       // Assertions
       if probe.config == nil {
           t.Error("expected config to be set")
       }
       
       probe.Close()
   }
   ```

3. Test with race detector:
   ```bash
   go test -race -v ./internal/probe/yourprobe/...
   ```

## Key Components

### 1. BaseProbe Responsibilities
- Lifecycle management (Initialize, Start, Stop, Close)
- Logging with probe name context
- Event reader management (perf/ringbuf)
- Context handling
- Running state tracking

### 2. BaseConfig Responsibilities  
- Common configuration fields (PID, UID, BTF mode, debug, etc.)
- Validation of common fields
- Kernel version checks
- Global variable support detection

### 3. Probe-Specific Responsibilities
- eBPF program management
- Probe configuration and attachment
- Event decoding
- Resource cleanup (files, connections, etc.)

### 4. Event Responsibilities
- Binary deserialization from eBPF
- Human-readable formatting
- Unique identification
- Validation

## Common Pitfalls

### 1. Field Name Mismatches in eBPF Structs
**Problem**: Event decoding fails due to field alignment or size mismatches between Go struct and eBPF C struct.

**Solution**: 
- Match field types exactly (uint32 in Go = u32 in C, etc.)
- Account for padding and alignment
- Use binary.Read with proper endianness (LittleEndian for most architectures)
- Consider using `pahole` to check C struct layout

### 2. Not Calling BaseProbe Methods
**Problem**: Missing initialization, improper cleanup, or no logging context.

**Solution**:
- Always call `p.BaseProbe.Initialize()` first in Initialize
- Always call `p.BaseProbe.Start()` first in Start
- Always call `p.BaseProbe.Close()` last in Close
- Use `p.Logger()` instead of creating new loggers

### 3. Map Name Mismatches
**Problem**: eBPF map names in code don't match names in kernel code.

**Solution**:
- Double-check map names in `kern/*.c` files
- Use exact names in `setupManager()`: `{Name: "events"}`
- Check with `bpftool map list` if debugging live

### 4. Not Handling Multiple Event Types
**Problem**: Probe has multiple eBPF maps but only decodes one event type.

**Solution**:
- Store all maps in `p.eventMaps`
- Check map index or name in `Decode()` method
- Return appropriate event type based on map

### 5. Forgetting to Update Tests
**Problem**: Tests fail after refactoring because they use old API.

**Solution**:
- Update all test functions to use new Initialize signature
- Add mockDispatcher
- Remove references to removed fields/methods
- Run tests with `-race` flag

### 6. Improper Error Handling
**Problem**: Using generic errors instead of domain-specific error types.

**Solution**:
- Use `errors.NewConfigurationError()` for config issues
- Use `errors.NewEBPFLoadError()` for eBPF loading issues
- Use `errors.NewEBPFAttachError()` for attachment issues
- Use `errors.NewEventDecodeError()` for event decoding issues

## Testing Strategy

### Unit Tests
1. Test `NewConfig()` and default values
2. Test `Config.Validate()` with valid and invalid inputs
3. Test `NewProbe()` creation
4. Test `Initialize()` with different configurations
5. Test `Close()` cleanup

### Integration Tests (Optional)
1. Test full probe lifecycle (Initialize → Start → Stop → Close)
2. Test event decoding with sample data
3. Test eBPF program loading (requires eBPF bytecode)

### Test Commands
```bash
# Run unit tests
go test -v ./internal/probe/yourprobe/...

# Run with race detector
go test -race -v ./internal/probe/yourprobe/...

# Run with coverage
go test -cover -v ./internal/probe/yourprobe/...

# Run specific test
go test -v ./internal/probe/yourprobe/... -run TestProbe_Initialize
```

## Checklist for Refactoring

Use this checklist when refactoring a probe:

- [ ] Config extends BaseConfig
- [ ] Config.NewConfig() initializes BaseConfig
- [ ] Config.Validate() calls BaseConfig.Validate() first
- [ ] Removed redundant methods from Config (GetPid, GetUid, etc.)
- [ ] NewProbe() initializes BaseProbe with probe name
- [ ] Initialize() calls BaseProbe.Initialize() first
- [ ] Initialize() does proper type assertion
- [ ] Initialize() logs relevant configuration
- [ ] Start() calls BaseProbe.Start() first
- [ ] Start() loads eBPF bytecode using GetBPFName()
- [ ] Start() sets up eBPF manager with setupManager()
- [ ] Start() initializes maps and starts event readers
- [ ] setupManager() configures probes and maps correctly
- [ ] getManagerOptions() includes constant editors for global vars
- [ ] Close() stops eBPF manager
- [ ] Close() cleans up probe-specific resources
- [ ] Close() calls BaseProbe.Close() last
- [ ] Events() returns eventMaps
- [ ] Events have DecodeFromBytes() method
- [ ] Events implement all domain.Event interface methods
- [ ] Decode() and GetDecoder() methods implemented
- [ ] Tests updated with mockDispatcher
- [ ] Tests pass with race detector
- [ ] Documentation updated if needed

## Examples

### Good Event Decoding Pattern
```go
func (e *MyEvent) DecodeFromBytes(data []byte) error {
    if len(data) < 24 {
        return errors.NewEventDecodeError("MyEvent", 
            fmt.Errorf("data too short: %d bytes", len(data)))
    }
    
    buf := bytes.NewBuffer(data)
    
    if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
        return errors.NewEventDecodeError("MyEvent.Timestamp", err)
    }
    
    if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
        return errors.NewEventDecodeError("MyEvent.Pid", err)
    }
    
    // ... more fields
    
    return nil
}
```

### Good Probe Setup Pattern
```go
func (p *Probe) setupManager() error {
    binaryPath := p.config.BinaryPath
    if binaryPath == "" {
        return errors.NewConfigurationError("binary_path required", nil)
    }
    
    p.Logger().Info().
        Str("binary_path", binaryPath).
        Msg("Setting up eBPF probes")
    
    p.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "uprobe/my_function",
                EbpfFuncName:     "uprobe_my_function",
                AttachToFuncName: "target_function",
                BinaryPath:       binaryPath,
            },
        },
        Maps: []*manager.Map{
            {Name: "events"},
        },
    }
    
    return nil
}
```

## Conclusion

Following this guide ensures:
1. **Consistency**: All probes follow the same architectural pattern
2. **Maintainability**: Common code is in BaseProbe/BaseConfig
3. **Testability**: Clear interfaces and separation of concerns
4. **Error handling**: Proper domain-specific error types
5. **Logging**: Structured logging with probe context

When in doubt, reference the `bash` probe implementation as the canonical example of this pattern.
