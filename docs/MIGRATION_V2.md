# Migration Guide: eCapture v2 Architecture

This guide helps you migrate from the old eCapture module system (`user/module/`) to the new v2 architecture (`internal/probe/`).

## Overview

The eCapture v2 architecture introduces a complete redesign based on clean architecture principles, design patterns, and best practices. While the old module system (`user/module/`) remains functional and will continue to work, it is deprecated and will be removed in v3.0.

## Why Migrate?

The new architecture provides significant improvements:

### Benefits of v2 Architecture

1. **Clean Architecture**: Clear separation between domain, business logic, and infrastructure
2. **Design Patterns**: Factory, Builder, Observer, Template Method, and Strategy patterns
3. **Better Testability**: 100% unit test coverage with comprehensive test suites
4. **Type Safety**: Strong typing and interfaces for all components
5. **Error Handling**: Structured errors with error codes and context
6. **Maintainability**: Smaller, focused modules with single responsibilities
7. **Extensibility**: Easy to add new probes following established patterns
8. **Documentation**: Comprehensive godoc and architecture documentation

### What's New in v2

- **Domain-Driven Design**: Core interfaces in `internal/domain/`
- **Unified Error Handling**: Structured errors in `internal/errors/`
- **Factory Pattern**: Centralized probe creation in `internal/factory/`
- **Builder Pattern**: Fluent configuration API in `internal/builder/`
- **Observer Pattern**: Event dispatching in `internal/events/`
- **Base Probe**: Template method pattern in `internal/probe/base/`
- **Comprehensive Tests**: Unit tests and E2E tests for all components

## Migration Timeline

- **v2.x**: Both architectures coexist (current state)
- **v3.0**: Old architecture removed (estimated Q2 2026)

**Recommendation**: Migrate to v2 architecture now to be ready for v3.0.

## Quick Comparison

### Old Architecture (Deprecated)

```go
// user/module/probe_bash.go
type MBashProbe struct {
    Module
    bpfManager *manager.Manager
    // ... many fields mixed together
}

// Creation
probe := module.NewBashProbe()
probe.Init(ctx, logger, config, writer)
probe.Run()
```

### New Architecture (Recommended)

```go
// internal/probe/bash/bash_probe.go
type Probe struct {
    *base.BaseProbe
    config *Config
    // ... focused fields
}

// Creation via factory
probe, err := factory.CreateProbe(factory.ProbeTypeBash)
config := bash.NewConfig()
probe.Initialize(ctx, config, dispatcher)
probe.Start(ctx)
```

## Step-by-Step Migration

### Step 1: Understand the New Structure

Each probe in the new architecture has four main components:

1. **Config** (`config.go`): Configuration with validation
2. **Event** (`event.go`): Event structure and decoding
3. **Probe** (`{probe}_probe.go`): Main probe implementation
4. **Register** (`register.go`): Factory registration

### Step 2: Migrate Configuration

#### Old Way (Deprecated)

```go
// Using old config
bc := config.NewBashConfig()
bc.Bashpath = "/bin/bash"
bc.ErrNo = 0
bc.Debug = true
```

#### New Way (Recommended)

```go
// Using new config with builder
config := builder.NewConfigBuilder().
    WithDebug(true).
    WithPid(os.Getpid()).
    Build()

// Or create config directly
bashConfig := bash.NewConfig()
bashConfig.SetDebug(true)
err := bashConfig.Validate()
```

### Step 3: Migrate Probe Creation

#### Old Way (Deprecated)

```go
// Direct instantiation
probe := module.NewBashProbe()
err := probe.Init(ctx, logger, config, writer)
if err != nil {
    return err
}
err = probe.Run()
```

#### New Way (Recommended)

```go
// Using factory pattern
probe, err := factory.CreateProbe(factory.ProbeTypeBash)
if err != nil {
    return err
}

// Initialize with config
config := bash.NewConfig()
dispatcher := events.NewDispatcher(logger)

err = probe.Initialize(ctx, config, dispatcher)
if err != nil {
    return err
}

// Start probe
err = probe.Start(ctx)
if err != nil {
    return err
}
```

### Step 4: Migrate Event Handling

#### Old Way (Deprecated)

```go
// Event handling mixed in probe
func (m *MBashProbe) DecodeBashEvent(data []byte) (*event.BashEvent, error) {
    // Decoding logic here
}
```

#### New Way (Recommended)

```go
// Separate event struct with decoding
type Event struct {
    BashType    uint32
    Pid         uint32
    Line        [256]uint8
    // ...
}

func (e *Event) DecodeFromBytes(data []byte) error {
    return binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
}

// Event dispatcher pattern
dispatcher.Register(func(event domain.Event) error {
    bashEvent := event.(*bash.Event)
    fmt.Printf("Captured command: %s\n", bashEvent.String())
    return nil
})
```

### Step 5: Migrate Error Handling

#### Old Way (Deprecated)

```go
// Simple errors
if err != nil {
    return fmt.Errorf("failed to start: %v", err)
}
```

#### New Way (Recommended)

```go
// Structured errors with codes and context
if err != nil {
    return errors.NewProbeStartError("bash", err).
        WithContext("pid", pid).
        WithContext("path", bashPath)
}
```

## Probe-Specific Migration

### Bash Probe Migration

#### Old Implementation
```go
import "github.com/gojue/ecapture/user/module"

probe := module.NewBashProbe()
config := config.NewBashConfig()
probe.Init(ctx, logger, config, writer)
probe.Run()
```

#### New Implementation
```go
import (
    "github.com/gojue/ecapture/internal/factory"
    "github.com/gojue/ecapture/internal/probe/bash"
    "github.com/gojue/ecapture/internal/events"
)

probe, err := factory.CreateProbe(factory.ProbeTypeBash)
config := bash.NewConfig()
config.SetBashPath("/bin/bash")

dispatcher := events.NewDispatcher(logger)
dispatcher.Register(handleBashEvent)

probe.Initialize(ctx, config, dispatcher)
probe.Start(ctx)
```

### MySQL Probe Migration

#### Old Implementation
```go
probe := module.NewMysqldProbe()
config := config.NewMysqldConfig()
probe.Init(ctx, logger, config, writer)
probe.Run()
```

#### New Implementation
```go
probe, err := factory.CreateProbe(factory.ProbeTypeMySQL)
config := mysql.NewConfig()
config.SetPid(mysqlPid)

dispatcher := events.NewDispatcher(logger)
dispatcher.Register(handleMySQLQuery)

probe.Initialize(ctx, config, dispatcher)
probe.Start(ctx)
```

### TLS Probes Migration (OpenSSL, GnuTLS, NSPR, GoTLS)

#### Old Implementation
```go
probe := module.NewOpenSSLProbe()
config := config.NewOpensslConfig()
config.Model = config.ModelText  // or ModelKeylog, ModelPcap
probe.Init(ctx, logger, config, writer)
probe.Run()
```

#### New Implementation
```go
probe, err := factory.CreateProbe(factory.ProbeTypeOpenSSL)
config := openssl.NewConfig()
config.SetCaptureMode("text")  // or "keylog", "pcap"
config.SetOpensslPath("/usr/lib/libssl.so.3")

dispatcher := events.NewDispatcher(logger)
dispatcher.Register(handleTLSData)

probe.Initialize(ctx, config, dispatcher)
probe.Start(ctx)
```

## Common Migration Patterns

### Pattern 1: Configuration Builder

```go
// Old
config := config.NewBashConfig()
config.Debug = true
config.Pid = 1234
config.Uid = 0

// New
config := builder.NewConfigBuilder().
    WithDebug(true).
    WithPid(1234).
    WithUid(0).
    Build()
```

### Pattern 2: Event Dispatching

```go
// Old - mixed with probe logic
func (p *MBashProbe) handleEvent(data []byte) {
    event, _ := p.DecodeBashEvent(data)
    fmt.Println(event.Command)
}

// New - observer pattern
dispatcher := events.NewDispatcher(logger)
dispatcher.Register(func(e domain.Event) error {
    bashEvent := e.(*bash.Event)
    fmt.Println(bashEvent.String())
    return nil
})
```

### Pattern 3: Lifecycle Management

```go
// Old
probe.Init(ctx, logger, config, writer)
probe.Run()
defer probe.Close()

// New
probe.Initialize(ctx, config, dispatcher)
probe.Start(ctx)
defer probe.Stop()
defer probe.Close()
```

## Testing Your Migration

### Unit Tests

```go
func TestMigration(t *testing.T) {
    // Test probe creation
    probe, err := factory.CreateProbe(factory.ProbeTypeBash)
    if err != nil {
        t.Fatalf("Failed to create probe: %v", err)
    }
    
    // Test configuration
    config := bash.NewConfig()
    if err := config.Validate(); err != nil {
        t.Fatalf("Config validation failed: %v", err)
    }
    
    // Test initialization
    dispatcher := events.NewDispatcher(logger)
    err = probe.Initialize(context.Background(), config, dispatcher)
    if err != nil {
        t.Fatalf("Initialization failed: %v", err)
    }
}
```

### E2E Tests

Run the comprehensive E2E test suite:

```bash
# Test bash probe
sudo make e2e-bash

# Test all probes
sudo make e2e
```

## Troubleshooting

### Issue: "probe type not registered"

```go
// Problem
probe, err := factory.CreateProbe(factory.ProbeTypeBash)
// Error: probe type not registered
```

**Solution**: Ensure you import the probe package to trigger `init()` registration:

```go
import _ "github.com/gojue/ecapture/internal/probe/bash"
```

### Issue: "config validation failed"

```go
// Problem
config := bash.NewConfig()
err := probe.Initialize(ctx, config, dispatcher)
// Error: config validation failed
```

**Solution**: Always validate and set required fields:

```go
config := bash.NewConfig()
config.SetBashPath("/bin/bash")
if err := config.Validate(); err != nil {
    log.Fatal(err)
}
```

### Issue: "event type mismatch"

```go
// Problem
dispatcher.Register(func(e domain.Event) error {
    bashEvent := e.(*bash.Event)  // panic: type assertion failed
    return nil
})
```

**Solution**: Check event type before assertion:

```go
dispatcher.Register(func(e domain.Event) error {
    bashEvent, ok := e.(*bash.Event)
    if !ok {
        return fmt.Errorf("unexpected event type: %T", e)
    }
    // Handle event
    return nil
})
```

## Migration Checklist

- [ ] Read this migration guide completely
- [ ] Review new architecture in `internal/` directory
- [ ] Understand the design patterns used
- [ ] Update probe creation to use factory pattern
- [ ] Update configuration to use new config types
- [ ] Update event handling to use observer pattern
- [ ] Update error handling to use structured errors
- [ ] Add unit tests for your migration
- [ ] Run E2E tests to validate functionality
- [ ] Update your documentation
- [ ] Plan for complete migration before v3.0

## Resources

### Documentation

- [Architecture Overview](../internal/ARCHITECTURE.md)
- [Implementation Plan](../internal/IMPLEMENTATION_PLAN.md)
- [E2E Testing Guide](./e2e-tests.md)
- [Phase 5 Summary](../internal/PHASE5_SUMMARY.md)

### Code References

- **Domain Interfaces**: `internal/domain/`
- **Error Handling**: `internal/errors/`
- **Factory Pattern**: `internal/factory/`
- **Builder Pattern**: `internal/builder/`
- **Base Probe**: `internal/probe/base/`
- **Example Probe**: `internal/probe/bash/`

### Community Support

- GitHub Issues: https://github.com/gojue/ecapture/issues
- GitHub Discussions: https://github.com/gojue/ecapture/discussions

## Frequently Asked Questions

### Q: When should I migrate?

**A**: As soon as possible. The old architecture will be removed in v3.0, so migrating now gives you time to test and validate.

### Q: Can I use both architectures simultaneously?

**A**: Yes, both architectures coexist in v2.x. The CLI currently uses the old architecture, while the new architecture is available for programmatic use.

### Q: Will my existing code break?

**A**: No, existing code continues to work. The old architecture is deprecated but fully functional. You can migrate at your own pace.

### Q: Is the new architecture production-ready?

**A**: Yes, the new architecture has 100% unit test coverage and comprehensive E2E tests. It's production-ready and recommended for all new development.

### Q: How do I contribute to the new architecture?

**A**: Follow the patterns established in existing probes (e.g., `internal/probe/bash/`). See `internal/ARCHITECTURE.md` for detailed guidelines.

## Conclusion

The v2 architecture represents a significant improvement in code quality, maintainability, and testability. While migration requires some effort, the benefits far outweigh the costs. We encourage all users to migrate before v3.0 to ensure a smooth transition.

For questions or assistance with migration, please open an issue on GitHub or join the discussion forums.

---

**Last Updated**: 2026-01-02  
**Version**: v2.0  
**Next Review**: Before v3.0 release
