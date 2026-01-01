# eCapture Internal Architecture

This directory contains the refactored internal architecture for eCapture, implementing clean architecture principles and design patterns for improved maintainability, testability, and extensibility.

## Directory Structure

```
internal/
├── domain/          # Core interfaces and contracts
├── errors/          # Unified error handling
├── logger/          # Logging abstraction
├── config/          # Configuration management
├── builder/         # Fluent configuration builders
├── events/          # Event dispatching (Observer pattern)
├── factory/         # Probe factory (Factory pattern)
└── probe/
    ├── base/        # Base probe implementation
    └── [probes]/    # Specific probe implementations
```

## Design Patterns

### 1. **Domain-Driven Design**
All core concepts are defined as interfaces in the `domain` package:
- `Probe`: Lifecycle management for eBPF probes
- `Event`: Event structure and processing
- `Configuration`: Probe configuration
- `EventDispatcher`: Event distribution

### 2. **Builder Pattern** (`builder/`)
Fluent API for configuration:
```go
config := NewConfigBuilder().
    WithPid(1234).
    WithDebug(true).
    Build()
```

### 3. **Observer Pattern** (`events/`)
Event dispatching to multiple handlers:
```go
dispatcher.Register(handler1)
dispatcher.Register(handler2)
dispatcher.Dispatch(event)  // Notifies all handlers
```

### 4. **Factory Pattern** (`factory/`)
Centralized probe creation:
```go
probe := factory.CreateProbe(ProbeTypeBash)
```

### 5. **Template Method Pattern** (`probe/base/`)
BaseProbe provides common functionality, concrete probes override specifics:
```go
type MyProbe struct {
    *base.BaseProbe
}

func (p *MyProbe) Start(ctx context.Context) error {
    // Call base implementation
    if err := p.BaseProbe.Start(ctx); err != nil {
        return err
    }
    // Add probe-specific logic
    return nil
}
```

## Error Handling

All errors use structured error types with error codes:

```go
// Create an error
err := errors.NewProbeStartError("openssl", cause)

// Add context
err.WithContext("pid", 1234).WithContext("uid", 0)

// Error codes
ErrCodeConfiguration  = 101
ErrCodeProbeInit      = 201
ErrCodeProbeStart     = 202
ErrCodeEventDecode    = 301
```

## Testing

All packages have comprehensive unit tests:
- `*_test.go` files alongside implementation
- Run tests: `go test ./internal/...`
- Run with race detector: `go test -race ./internal/...`
- Coverage: `go test -cover ./internal/...`

### Test Coverage Status
- ✅ `errors`: 100% (all error types and wrapping)
- ✅ `config`: 100% (validation and setters/getters)
- ✅ `builder`: 100% (fluent API)
- ✅ `events`: 100% (dispatcher and handlers)
- ✅ `factory`: 100% (probe creation)
- ✅ `probe/base`: 100% (lifecycle and event loops)

## Creating a New Probe

### Step 1: Define Configuration
```go
// internal/probe/myprobe/config.go
type MyProbeConfig struct {
    *config.BaseConfig
    SpecificField string
}

func (c *MyProbeConfig) Validate() error {
    if err := c.BaseConfig.Validate(); err != nil {
        return err
    }
    // Add specific validation
    return nil
}
```

### Step 2: Define Events
```go
// internal/probe/myprobe/event.go
type MyEvent struct {
    Pid  uint32
    Data []byte
}

func (e *MyEvent) DecodeFromBytes(data []byte) error {
    // Implement decoding using binary.Read
    return nil
}

func (e *MyEvent) Validate() error {
    // Validate event data
    return nil
}
```

### Step 3: Implement Probe
```go
// internal/probe/myprobe/myprobe.go
type MyProbe struct {
    *base.BaseProbe
    manager *manager.Manager
}

func NewMyProbe() (*MyProbe, error) {
    return &MyProbe{
        BaseProbe: base.NewBaseProbe("myprobe"),
    }, nil
}

func (p *MyProbe) Start(ctx context.Context) error {
    if err := p.BaseProbe.Start(ctx); err != nil {
        return err
    }
    
    // Load eBPF program
    // Attach probes
    // Start event readers
    
    return nil
}
```

### Step 4: Register with Factory
```go
// internal/probe/myprobe/register.go
func init() {
    factory.RegisterProbe(factory.ProbeTypeMyProbe, func() (domain.Probe, error) {
        return NewMyProbe()
    })
}
```

### Step 5: Add Tests
```go
// internal/probe/myprobe/myprobe_test.go
func TestMyProbe(t *testing.T) {
    probe, err := NewMyProbe()
    // Test initialization, lifecycle, etc.
}
```

## Best Practices

### Error Handling
1. Always use structured errors from `internal/errors`
2. Add context to errors with `WithContext()`
3. Wrap lower-level errors appropriately

### Logging
1. Use structured logging with `internal/logger`
2. Add contextual fields (probe, pid, uid)
3. Use appropriate log levels

### Resource Management
1. Always implement `Close()` for cleanup
2. Use `defer` for guaranteed cleanup
3. Close resources in reverse initialization order

### Testing
1. Test all public interfaces
2. Test error conditions
3. Test concurrent access where applicable
4. Use table-driven tests for multiple cases

## Migration Status

### Completed
- ✅ Domain interfaces
- ✅ Error handling system
- ✅ Configuration management
- ✅ Builder pattern
- ✅ Event dispatcher
- ✅ Factory pattern
- ✅ BaseProbe implementation

### In Progress
- 🔄 Individual probe migrations

### Planned
- ⏳ CLI integration
- ⏳ End-to-end tests
- ⏳ Documentation updates

## Performance Considerations

- Event loops use non-blocking reads
- Context-based cancellation for graceful shutdown
- Atomic operations for state management
- Minimal allocations in hot paths
- Resource pooling where applicable

## Backward Compatibility

- Old probe implementations in `user/module/` remain functional
- CLI interface unchanged
- Configuration format compatible
- Can run old and new probes simultaneously

## Contributing

When adding new functionality:
1. Follow existing patterns and structures
2. Add comprehensive tests
3. Document public APIs
4. Update this README
5. Ensure backward compatibility
