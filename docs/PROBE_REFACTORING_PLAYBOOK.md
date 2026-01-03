# Probe Module Refactoring Playbook

## Overview

This document captures the comprehensive process, lessons learned, and best practices from refactoring the GoTLS probe module to follow the standardized architecture pattern. Use this as a guide when refactoring other probe modules (openssl, gnutls, mysql, postgres, nspr, zsh).

## Goals

The refactoring effort aims to achieve:

1. **Architectural Consistency**: All probes follow the same standardized pattern established by the bash probe
2. **Code Quality**: Proper separation of concerns, clear interfaces, comprehensive testing
3. **Maintainability**: Shared utilities, reduced code duplication, clear documentation
4. **Correctness**: Event structures match kernel definitions, proper lifecycle management
5. **Feature Completeness**: All capture modes working correctly with proper validation

## Refactoring Process

### Phase 1: Analysis & Planning

#### Step 1.1: Review Reference Implementation
- **Action**: Study `internal/probe/bash/bash_probe.go` as the canonical template
- **Key Elements**:
  - Config extends `config.BaseConfig`
  - Probe embeds `base.BaseProbe`
  - Implements `domain.Probe` interface fully
  - Implements `domain.EventDecoder` interface
  - Events implement `domain.Event` interface
  - Factory registration pattern

#### Step 1.2: Examine Current State
- **Action**: Analyze the target probe's current implementation
- **Check**:
  - Config structure and inheritance
  - Probe lifecycle methods (Initialize, Start, Stop, Close)
  - Event structures and their kernel counterparts
  - eBPF manager setup and probe attachments
  - Mode-specific logic and branching

#### Step 1.3: Review Historical Code
- **Action**: Check git history for previous implementations
- **Look For**:
  - Original probe setup patterns (e.g., `user/module/probe_gotls*.go`)
  - Event structures (e.g., `user/event/event_gotls.go`)
  - Configuration patterns (e.g., `user/config/config_gotls.go`)
  - Mode-specific implementations (text, keylog, pcap)

#### Step 1.4: Examine Kernel Code
- **Action**: Study the eBPF kernel programs
- **Verify**:
  - Event structure definitions (must match exactly)
  - Map names and types
  - Probe function names and signatures
  - Constants (buffer sizes, offsets, etc.)

### Phase 2: Core Refactoring

#### Step 2.1: Update Configuration
```go
// BEFORE: Standalone config
type Config struct {
    Pid uint32
    // ... other fields
}

// AFTER: Extends BaseConfig
type Config struct {
    config.BaseConfig
    // Probe-specific fields
    IsRegisterABI       bool
    ReadTlsAddrs        []uint64
    GoTlsWriteAddr      uint64
    GoTlsMasterSecretAddr uint64
    // ... other fields
}

func (c *Config) Validate() error {
    // Chain base validation first
    if err := c.BaseConfig.Validate(); err != nil {
        return err
    }
    // Then probe-specific validation
    return nil
}
```

**Key Points**:
- Extend `config.BaseConfig` to inherit PID/UID filtering, BTF mode, debug flags
- Remove redundant field definitions and methods now in base
- Keep probe-specific configuration separate
- Chain validation calls properly

#### Step 2.2: Update Probe Structure
```go
// Embed BaseProbe
type Probe struct {
    base.BaseProbe
    // Probe-specific fields
    manager    *manager.Manager
    keylogFile *os.File
    pcapWriter *handlers.PcapWriter
}

func NewProbe(cfg config.ProbeConfig) (domain.Probe, error) {
    p := &Probe{}
    if err := p.BaseProbe.Init(cfg); err != nil {
        return nil, err
    }
    return p, nil
}
```

**Key Points**:
- Embed `base.BaseProbe` for standard lifecycle
- Keep probe-specific state minimal
- Initialize BaseProbe in constructor
- Return `domain.Probe` interface

#### Step 2.3: Implement Initialize Method
```go
func (p *Probe) Initialize(ctx context.Context, logger *zap.Logger, _ domain.Dispatcher) error {
    // Type assert config
    gtlsConf, ok := p.Conf.(*Config)
    if !ok {
        return errors.NewConfigError("invalid config type")
    }
    
    // Open output files based on mode
    if err := p.openOutputFiles(gtlsConf); err != nil {
        return err
    }
    
    // Find symbol offsets
    if err := gtlsConf.findSymbolOffsets(); err != nil {
        return err
    }
    
    logger.Info("GoTLS probe initialized",
        zap.String("elfPath", gtlsConf.ElfPath),
        zap.String("mode", gtlsConf.CaptureMode))
    
    return nil
}
```

**Key Points**:
- Type assert config early
- Open files/resources based on mode
- Parse symbols and offsets
- Log initialization details
- Handle errors with domain-specific types

#### Step 2.4: Implement Start Method
```go
func (p *Probe) Start(ctx context.Context) error {
    gtlsConf := p.Conf.(*Config)
    
    // Setup eBPF manager
    if err := p.setupManager(gtlsConf); err != nil {
        return err
    }
    
    // Initialize and start manager
    if err := p.manager.Init(p.GetBytecode()); err != nil {
        return errors.NewProbeStartError("gotls", err)
    }
    
    if err := p.manager.Start(); err != nil {
        return errors.NewProbeStartError("gotls", err)
    }
    
    // Start event readers
    return p.startEventReaders(ctx)
}
```

**Key Points**:
- Setup eBPF manager with probes and maps
- Load bytecode and initialize
- Start manager before event readers
- Use domain-specific error types

#### Step 2.5: Implement setupManager Method
```go
func (p *Probe) setupManager(conf *Config) error {
    var probes []manager.Probe
    var maps []manager.Map
    
    // Base event map (used by most modes)
    maps = append(maps, manager.Map{Name: "events"})
    
    // Mode-specific probe and map setup
    switch conf.CaptureMode {
    case "text":
        // TEXT mode: Only TLS read/write probes
        probes = append(probes, p.getWriteProbe(conf))
        probes = append(probes, p.getReadProbes(conf)...)
        
    case "key", "keylog":
        // KEYLOG mode: Only master secret probe
        probes = append(probes, p.getMasterSecretProbe(conf))
        maps = append(maps, manager.Map{Name: "mastersecret_go_events"})
        
    case "pcap", "pcapng":
        // PCAP mode: TC probes + master secret probe
        probes = append(probes, p.getTCProbes(conf)...)
        probes = append(probes, p.getMasterSecretProbe(conf))
        maps = append(maps, p.getTCMaps()...)
        maps = append(maps, manager.Map{Name: "mastersecret_go_events"})
    }
    
    p.manager = &manager.Manager{
        Probes: probes,
        Maps:   maps,
    }
    return nil
}
```

**Key Points**:
- Initialize probes and maps arrays
- Mode-specific logic with clear separation
- Use UAddress for absolute addressing (not UprobeOffset)
- Explicit EbpfFuncName assignments
- Order matters: write probe first, then reads

#### Step 2.6: Update Event Structures
```go
// Match kernel struct exactly
type TLSDataEvent struct {
    Ts         uint64
    Pid        uint32
    Tid        uint32
    DataLen    int32    // Changed from uint32 to match kernel
    Comm       [16]byte
    Data       [16384]byte // MAX_DATA_SIZE_OPENSSL
    // ... other fields matching kernel definition
}

func (e *TLSDataEvent) DecodeFromBytes(data []byte) error {
    if len(data) < 32 {
        return errors.NewEventDecodeError("TLSDataEvent", 
            fmt.Errorf("insufficient data"))
    }
    // Decode matching kernel struct layout
    return nil
}

func (e *TLSDataEvent) Validate() error {
    return nil // Implement validation logic
}

// Implement other domain.Event methods...
```

**Key Points**:
- Match kernel struct definitions **exactly**
- Use correct field types (int32 vs uint32 matters!)
- Use correct buffer sizes (16KB for TLS data)
- Implement full `domain.Event` interface
- Use domain-specific error types

#### Step 2.7: Implement EventDecoder Interface
```go
func (p *Probe) Decode(eventType domain.EventType, data []byte) (domain.Event, error) {
    switch eventType {
    case domain.EventTypeGoTLSData:
        event := &TLSDataEvent{}
        if err := event.DecodeFromBytes(data); err != nil {
            return nil, err
        }
        // Write to keylog file if applicable
        return event, nil
        
    case domain.EventTypeGoTLSMasterSecret:
        event := &MasterSecretEvent{}
        if err := event.DecodeFromBytes(data); err != nil {
            return nil, err
        }
        // Write master secret to file(s)
        if p.keylogFile != nil {
            p.writeMasterSecretToFile(event)
        }
        if p.pcapWriter != nil {
            p.pcapWriter.WriteMasterSecret(event)
        }
        return event, nil
        
    default:
        return nil, fmt.Errorf("unknown event type: %v", eventType)
    }
}

func (p *Probe) GetDecoder() domain.EventDecoder {
    return p
}
```

**Key Points**:
- Decode based on event type
- Write side effects (files, pcap) during decode
- Return decoded events
- Self-reference for GetDecoder

#### Step 2.8: Implement Factory Registration
```go
// register.go
package gotls

import (
    "github.com/gojue/ecapture/internal/domain"
    "github.com/gojue/ecapture/pkg/config"
)

func init() {
    domain.RegisterProbeFactory("gotls", func(cfg config.ProbeConfig) (domain.Probe, error) {
        return NewProbe(cfg)
    })
}
```

**Key Points**:
- Create separate register.go file
- Use init() function for registration
- Follow bash probe pattern exactly

### Phase 3: Special Features

#### Step 3.1: Symbol Parsing (Go-Specific)
```go
func (c *Config) findSymbolOffsets() error {
    // For Go binaries, use debug/gosym not ELF symbol table
    table, err := readGoSymbolTable(c.ElfPath)
    if err != nil {
        return err
    }
    
    // Find required symbols
    writeFunc := table.LookupFunc("crypto/tls.(*Conn).writeRecordLocked")
    if writeFunc != nil {
        c.GoTlsWriteAddr = writeFunc.Value
    }
    
    // Find read functions
    c.ReadTlsAddrs = []uint64{}
    // ... iterate and find multiple read function offsets
    
    return nil
}

func readGoSymbolTable(elfPath string) (*gosym.Table, error) {
    f, err := os.Open(elfPath)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    
    elfFile, err := elf.Open(elfPath)
    if err != nil {
        return nil, err
    }
    defer elfFile.Close()
    
    // Find gopclntab section
    section := elfFile.Section(".gopclntab")
    if section == nil {
        return nil, fmt.Errorf("no .gopclntab section")
    }
    
    // Parse Go symbol table
    // ... use gosym.NewTable with proper magic number
}
```

**Key Points**:
- Go binaries need special handling via gopclntab
- Use `debug/gosym` and `debug/buildinfo` packages
- Handle different Go versions (magic numbers)
- Store addresses in config for probe attachment
- Add comprehensive unit tests with real Go binary

#### Step 3.2: PCAP/PCAPNG Support
```go
// Create shared pcap_writer.go in internal/probe/base/handlers/
type PcapWriter struct {
    writer    *pcapgo.NgWriter
    file      *os.File
    interface *pcapgo.NgInterface
}

func NewPcapWriter(filename string, ifname string) (*PcapWriter, error) {
    file, err := os.Create(filename)
    if err != nil {
        return nil, err
    }
    
    // Create PCAPNG writer
    writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
    if err != nil {
        file.Close()
        return nil, err
    }
    
    // Add interface with branding
    iface := pcapgo.NgInterface{
        Name:       "eCapture(旁观者)",
        LinkType:   layers.LinkTypeEthernet,
        // ... other fields
    }
    
    return &PcapWriter{
        writer:    writer,
        file:      file,
        interface: &iface,
    }, nil
}

func (pw *PcapWriter) WriteMasterSecret(event *MasterSecretEvent) error {
    // Format as NSS SSLKEYLOGFILE format
    keylog := fmt.Sprintf("%s %s %s\n",
        event.GetLabel(),
        event.GetClientRandom(),
        event.GetSecret())
    
    // Write to PCAPNG DSB block
    return pw.writer.WriteDecryptionSecretsBlock(
        pcapgo.DSB_SECRETS_TYPE_TLS,
        []byte(keylog))
}

func (pw *PcapWriter) Close() error {
    pw.Flush()
    return pw.file.Close()
}
```

**Key Points**:
- Place in shared location: `internal/probe/base/handlers/`
- Use custom gopacket fork: `github.com/cfc4n/gopacket v1.1.20`
- Use pcapgo constants: `pcapgo.DSB_SECRETS_TYPE_TLS`
- Proper branding: "eCapture(旁观者)"
- Implement Flush() and Close() properly

#### Step 3.3: Keylog File Writing
```go
func (p *Probe) writeMasterSecretToFile(event *MasterSecretEvent) error {
    if p.keylogFile == nil {
        return nil
    }
    
    // NSS SSLKEYLOGFILE format
    line := fmt.Sprintf("%s %s %s\n",
        strings.TrimSpace(string(event.Label[:event.LabelLen])),
        hex.EncodeToString(event.ClientRandom[:event.ClientRandomLen]),
        hex.EncodeToString(event.Secret[:event.SecretLen]))
    
    _, err := p.keylogFile.WriteString(line)
    return err
}
```

**Key Points**:
- Write immediately when event decoded
- NSS SSLKEYLOGFILE format: "LABEL CLIENTRANDOM SECRET"
- Hex encode binary data
- Compatible with Wireshark

### Phase 4: Testing & Validation

#### Step 4.1: Unit Tests
```go
func TestProbe_Initialize(t *testing.T) {
    // Test basic initialization
}

func TestProbe_Decode_TLSDataEvent(t *testing.T) {
    // Test event decoding
}

func TestFindSymbolOffsets(t *testing.T) {
    // Test symbol finding with real Go binary
    // Compile examples/https_client/golang_https.go
    // Verify offsets found correctly
}
```

**Key Points**:
- Test all lifecycle methods
- Test event decoding with real data
- Test symbol parsing with compiled binaries
- Test mode-specific logic
- Mock dependencies appropriately

#### Step 4.2: Build & Lint
```bash
# Run tests with race detector
go test -race ./internal/probe/gotls/...

# Run go vet
go vet ./internal/probe/gotls/...

# Format code
go fmt ./internal/probe/gotls/...

# Build CLI to verify
go build ./cli/cmd/
```

**Key Points**:
- Always run with race detector
- Fix all vet warnings
- Format consistently
- Build full binary to catch integration issues

#### Step 4.3: Manual Validation
```bash
# Test text mode
./ecapture gotls -m text -w /tmp/gotls.log

# Test keylog mode
./ecapture gotls -m keylog --keylogfile /tmp/keys.log

# Test pcap mode
./ecapture gotls -m pcap --pcapfile /tmp/capture.pcapng \
  --keylogfile /tmp/keys.log
```

**Key Points**:
- Test each mode independently
- Verify output files created
- Check file formats (keylog, pcapng)
- Test with real Go applications

### Phase 5: Documentation

#### Step 5.1: Update Code Comments
- Document all exported types and functions
- Explain complex logic (symbol parsing, mode branching)
- Add references to kernel code where applicable
- Document gotchas and edge cases

#### Step 5.2: Create Refactoring Guide
- Document architecture patterns
- Explain key decisions
- Provide code examples
- List common pitfalls

#### Step 5.3: Write Summary Document
- Goals and objectives
- What was changed
- Testing results
- Next steps

## Common Pitfalls & Solutions

### Pitfall 1: Event Structure Mismatch
**Problem**: Event struct doesn't match kernel definition
**Solution**: 
- Always check kernel `.c` file for exact struct
- Pay attention to field types (int32 vs uint32)
- Match buffer sizes exactly (MAX_DATA_SIZE constants)
- Test with real eBPF events

### Pitfall 2: Incorrect Probe Addressing
**Problem**: Using UprobeOffset instead of UAddress
**Solution**:
- Always use UAddress for absolute addressing
- Calculate address from symbol lookup
- Never use relative offsets

### Pitfall 3: Mode Logic Overlap
**Problem**: Multiple modes loading same probes
**Solution**:
- Use switch statement for mode-specific setup
- Don't reuse probe initialization across modes
- Text mode != Keylog mode != PCAP mode
- Test each mode independently

### Pitfall 4: Missing Factory Registration
**Problem**: Probe not available at runtime
**Solution**:
- Create register.go file
- Use init() function
- Follow bash probe pattern exactly
- Import register package in main

### Pitfall 5: Symbol Parsing Errors
**Problem**: Can't find symbols in binary
**Solution**:
- For Go: Use debug/gosym with gopclntab
- For C/C++: Use ELF symbol table
- Handle stripped binaries gracefully
- Add comprehensive tests with real binaries

### Pitfall 6: File Handle Leaks
**Problem**: Resources not cleaned up
**Solution**:
- Implement proper Close() method
- Close files in reverse order of opening
- Use defer for cleanup
- Test with resource leak detector

### Pitfall 7: Type Assertion Failures
**Problem**: Config type assertion panics
**Solution**:
- Always check type assertion: `cfg, ok := x.(*Config)`
- Return proper errors on mismatch
- Initialize with correct config type
- Add type checks in NewProbe

### Pitfall 8: PCAPNG Format Issues
**Problem**: Invalid PCAPNG files
**Solution**:
- Use custom gopacket fork (cfc4n/gopacket v1.1.20)
- Use pcapgo constants (DSB_SECRETS_TYPE_TLS)
- Flush writer before close
- Test with Wireshark

## Iteration Summary: GoTLS Refactoring

### Iteration 1: Core Architecture
- Extended Config from BaseConfig
- Embedded BaseProbe in Probe
- Implemented Initialize/Start/Close lifecycle
- Fixed type cast issues

**Result**: Basic probe structure established

### Iteration 2: Factory & Registration
- Added register.go with factory pattern
- Registered probe in domain
- Fixed config field access

**Result**: Probe discoverable at runtime

### Iteration 3: eBPF Manager Setup
- Implemented setupManager with proper ordering
- Fixed probe and map initialization
- Used explicit EbpfFuncName assignments

**Result**: eBPF programs loadable

### Iteration 4: Symbol Parsing
- Implemented findSymbolOffsets with debug/gosym
- Added readGoSymbolTable for Go binaries
- Handled multiple Go versions
- Added comprehensive unit tests

**Result**: Correct probe attachment points

### Iteration 5: Event Structures
- Fixed TLSDataEvent to match kernel (int32, 16KB)
- Rewrote MasterSecretEvent to match mastersecret_gotls_t
- Implemented domain.Event interface

**Result**: Events decode correctly

### Iteration 6: UAddress Migration
- Changed all UprobeOffset to UAddress
- Used symbol addresses from table
- Fixed probe attachment

**Result**: Probes attach at correct addresses

### Iteration 7: Mode Separation
- Separated text/keylog/pcap mode logic
- Fixed probe selection per mode
- Removed probe overlap

**Result**: Each mode loads only required probes

### Iteration 8: Keylog Support
- Added GoTlsMasterSecretAddr field
- Implemented keylog file writing
- Added NSS SSLKEYLOGFILE format

**Result**: TLS keys exportable

### Iteration 9: PCAP Support
- Normalized pcap/pcapng modes
- Added PcapWriter class
- Implemented DSB writing
- Added TC probe support

**Result**: Network capture with TLS decryption keys

### Iteration 10: Shared Utilities
- Moved pcap_writer.go to base/handlers/
- Used pcapgo constants
- Fixed syntax errors

**Result**: Reusable across all probes

## Next Modules to Refactor

Apply this playbook to refactor the following probe modules in order:

1. **openssl** - Similar to gotls but for OpenSSL/BoringSSL
   - Already has extensive mode support
   - Complex symbol requirements
   - PCAP support needed

2. **gnutls** - GnuTLS library probe
   - Multiple version support
   - Symbol parsing complexity
   - Similar modes as gotls

3. **nspr** - NSS/NSPR library probe
   - Firefox/Thunderbird support
   - Unique symbol patterns

4. **mysql** - MySQL/MariaDB protocol
   - Text protocol capture
   - Query logging

5. **postgres** - PostgreSQL protocol
   - Similar to mysql
   - Protocol parsing

6. **zsh** - ZSH shell commands
   - Similar to bash
   - Simpler refactoring

## Success Metrics

For each refactored probe:

✅ Config extends BaseConfig
✅ Probe embeds BaseProbe  
✅ All interfaces implemented (Probe, EventDecoder, Event)
✅ Factory registered
✅ Events match kernel structs exactly
✅ All modes work independently
✅ Unit tests pass with race detector
✅ go vet clean
✅ Code formatted
✅ Documentation complete
✅ Manual testing successful

## Maintenance Guidelines

### After Refactoring
1. Keep probes aligned with bash pattern
2. Update shared utilities together
3. Maintain comprehensive tests
4. Document all changes
5. Review kernel code changes regularly

### When Kernel Code Changes
1. Update event structures
2. Update probe attachments
3. Update tests
4. Verify all modes still work

### When Adding New Features
1. Implement in one probe first
2. Generalize to shared utilities
3. Roll out to other probes
4. Update documentation

## Conclusion

This playbook captures the systematic approach and lessons learned from refactoring the GoTLS probe. Follow these steps, avoid the documented pitfalls, and use the iteration pattern to successfully refactor other probe modules.

The key to success is:
- **Thorough analysis** before coding
- **Incremental changes** with validation
- **Comprehensive testing** at each step
- **Clear documentation** throughout
- **Learning from errors** and iterating

Good luck with your refactoring work!
