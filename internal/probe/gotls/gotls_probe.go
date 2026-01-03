// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gotls

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
)

// Probe represents the GoTLS probe
type Probe struct {
	*base.BaseProbe
	config     *Config
	bpfManager *manager.Manager
	eventMaps  []*ebpf.Map

	// File handles for different capture modes
	keylogFile *os.File
	pcapFile   *os.File
}

// NewProbe creates a new GoTLS probe
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe: base.NewBaseProbe("gotls"),
	}, nil
}

// Initialize initializes the probe with the given configuration
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	// Type assert to GoTLS-specific config
	gotlsConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for gotls probe", nil)
	}
	p.config = gotlsConfig

	p.Logger().Info().
		Str("go_version", gotlsConfig.GoVersion).
		Bool("is_register_abi", gotlsConfig.IsRegisterABI).
		Str("capture_mode", gotlsConfig.CaptureMode).
		Str("elf_path", gotlsConfig.ElfPath).
		Msg("GoTLS probe initialized")

	// Open output files based on capture mode
	if err := p.openOutputFiles(); err != nil {
		return err
	}

	return nil
}

// openOutputFiles opens output files based on capture mode
func (p *Probe) openOutputFiles() error {
	switch p.config.CaptureMode {
	case "keylog", "key":
		if p.config.KeylogFile == "" {
			return errors.NewConfigurationError("keylog_file is required for keylog mode", nil)
		}
		file, err := os.OpenFile(p.config.KeylogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return errors.NewConfigurationError("failed to open keylog file", err)
		}
		p.keylogFile = file

	case "pcap", "pcapng":
		if p.config.PcapFile == "" {
			return errors.NewConfigurationError("pcap_file is required for pcap mode", nil)
		}
		file, err := os.OpenFile(p.config.PcapFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return errors.NewConfigurationError("failed to open pcap file", err)
		}
		p.pcapFile = file
		
		// For pcapng mode, optionally open keylog file if specified
		// Master secrets can be embedded in PCAPNG DSB blocks or written to separate keylog
		if p.config.KeylogFile != "" {
			keylogFile, err := os.OpenFile(p.config.KeylogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				p.Logger().Warn().Err(err).Msg("Failed to open keylog file for pcapng mode, will embed in DSB only")
			} else {
				p.keylogFile = keylogFile
			}
		}

	case "text":
		// Text mode uses stdout, no file to open
	default:
		return errors.NewConfigurationError("invalid capture mode", fmt.Errorf("mode: %s", p.config.CaptureMode))
	}

	return nil
}

// Start begins the gotls probe operation.
func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	// Load eBPF bytecode
	bpfFileName := p.BaseProbe.GetBPFName("bytecode/" + p.config.GetBPFFileName())
	p.Logger().Info().Str("file", bpfFileName).Msg("Loading eBPF bytecode")

	// Load from assets
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return errors.NewEBPFLoadError(bpfFileName, err)
	}

	// Setup eBPF manager
	if err := p.setupManager(); err != nil {
		return err
	}

	// Initialize eBPF manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), p.getManagerOptions()); err != nil {
		return errors.NewEBPFLoadError("gotls manager init", err)
	}

	// Start eBPF manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("gotls manager start", err)
	}

	// Get event maps
	eventsMap, found, err := p.bpfManager.GetMap("events")
	if err != nil {
		return errors.Wrap(errors.ErrCodeEBPFMapAccess, "failed to get events map", err)
	}
	if !found {
		return errors.NewResourceNotFoundError("eBPF map: events")
	}

	// Get master secret events map if in keylog mode
	var masterSecretMap *ebpf.Map
	if p.config.CaptureMode == "keylog" {
		masterSecretMap, found, err = p.bpfManager.GetMap("mastersecret_go_events")
		if err != nil {
			return errors.Wrap(errors.ErrCodeEBPFMapAccess, "failed to get mastersecret_go_events map", err)
		}
		if !found {
			p.Logger().Warn().Msg("Master secret map not found, keylog capture may be incomplete")
		}
	}

	// Store event maps
	if masterSecretMap != nil {
		p.eventMaps = []*ebpf.Map{eventsMap, masterSecretMap}
	} else {
		p.eventMaps = []*ebpf.Map{eventsMap}
	}

	// Start event readers
	if err := p.StartPerfEventReader(eventsMap, p); err != nil {
		return err
	}

	if masterSecretMap != nil {
		if err := p.StartPerfEventReader(masterSecretMap, p); err != nil {
			return err
		}
	}

	p.Logger().Info().Msg("GoTLS probe started successfully")
	return nil
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	return p.eventMaps
}

// Close closes the probe and releases resources
func (p *Probe) Close() error {
	// Stop eBPF manager
	if p.bpfManager != nil {
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to stop eBPF manager")
		}
	}

	// Close file handles
	if p.keylogFile != nil {
		if err := p.keylogFile.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close keylog file")
		}
		p.keylogFile = nil
	}

	if p.pcapFile != nil {
		if err := p.pcapFile.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close pcap file")
		}
		p.pcapFile = nil
	}

	return p.BaseProbe.Close()
}

// Decode implements EventDecoder interface.
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
	// Determine event type based on map
	for i, m := range p.eventMaps {
		if m == em {
			// First map is always events (TLS data)
			if i == 0 || len(p.eventMaps) == 1 {
				event := &TLSDataEvent{}
				if err := event.DecodeFromBytes(data); err != nil {
					return nil, err
				}
				return event, nil
			}
			// Second map is mastersecret_go_events (if exists)
			if i == 1 {
				event := &MasterSecretEvent{}
				if err := event.DecodeFromBytes(data); err != nil {
					return nil, err
				}
				// Write master secret to keylog file if in keylog or pcapng mode
				if err := p.writeMasterSecretToFile(event); err != nil {
					p.Logger().Warn().Err(err).Msg("Failed to write master secret to file")
				}
				return event, nil
			}
		}
	}
	return nil, fmt.Errorf("unknown eBPF map: %s", em.String())
}

// writeMasterSecretToFile writes a master secret event to the appropriate output file
func (p *Probe) writeMasterSecretToFile(event *MasterSecretEvent) error {
	if event == nil {
		return nil
	}

	// Only write to keylog file in keylog or pcapng mode
	if p.config.CaptureMode != "keylog" && p.config.CaptureMode != "key" && 
	   p.config.CaptureMode != "pcap" && p.config.CaptureMode != "pcapng" {
		return nil
	}

	// Ensure we have a file to write to
	var file *os.File
	if p.config.CaptureMode == "keylog" || p.config.CaptureMode == "key" {
		file = p.keylogFile
	} else if p.config.CaptureMode == "pcap" || p.config.CaptureMode == "pcapng" {
		// For pcapng mode, we also write to keylog file (DSB block handling)
		// If keylogFile is set, use it; otherwise, pcapFile will handle DSB internally
		file = p.keylogFile
		if file == nil {
			// TODO: In pcapng mode, master secrets should be written to DSB blocks
			// For now, we'll just log them
			p.Logger().Debug().
				Str("label", event.GetLabel()).
				Int("client_random_len", len(event.GetClientRandom())).
				Int("secret_len", len(event.GetSecret())).
				Msg("Master secret event (will be added to PCAPNG DSB)")
			return nil
		}
	}

	if file == nil {
		return fmt.Errorf("keylog file not open")
	}

	// Format: LABEL CLIENTRANDOM SECRET
	// This follows the NSS Key Log Format used by Wireshark
	label := event.GetLabel()
	clientRandom := fmt.Sprintf("%x", event.GetClientRandom())
	secret := fmt.Sprintf("%x", event.GetSecret())

	keylogLine := fmt.Sprintf("%s %s %s\n", label, clientRandom, secret)
	
	if _, err := file.WriteString(keylogLine); err != nil {
		return fmt.Errorf("failed to write to keylog file: %w", err)
	}

	// Sync to ensure data is written
	if err := file.Sync(); err != nil {
		p.Logger().Warn().Err(err).Msg("Failed to sync keylog file")
	}

	p.Logger().Debug().
		Str("label", label).
		Str("client_random", clientRandom[:16]+"..."). // Log only first 16 chars
		Msg("Master secret written to keylog file")

	return nil
}

// GetDecoder implements EventDecoder interface.
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	for i, m := range p.eventMaps {
		if m == em {
			if i == 0 || len(p.eventMaps) == 1 {
				return &TLSDataEvent{}, true
			}
			if i == 1 {
				return &MasterSecretEvent{}, true
			}
		}
	}
	return nil, false
}

// setupManager configures the eBPF manager with probes.
func (p *Probe) setupManager() error {
	elfPath := p.config.ElfPath
	if elfPath == "" {
		// Try to find Go binary in common locations
		// For now, we'll require ElfPath to be set
		return errors.NewConfigurationError("elf_path is required for GoTLS probe", nil)
	}

	// Determine which uprobes to attach based on ABI
	var writeSection, readSection, masterSecretSection string
	var writeFunc, readFunc, masterSecretFunc string
	
	if p.config.IsRegisterABI {
		writeSection = "uprobe/gotls_write_register"
		writeFunc = "gotls_write_register"
		readSection = "uprobe/gotls_read_register"
		readFunc = "gotls_read_register"
		masterSecretSection = "uprobe/gotls_mastersecret_register"
		masterSecretFunc = "gotls_mastersecret_register"
	} else {
		writeSection = "uprobe/gotls_write_stack"
		writeFunc = "gotls_write_stack"
		readSection = "uprobe/gotls_read_stack"
		readFunc = "gotls_read_stack"
		masterSecretSection = "uprobe/gotls_mastersecret_stack"
		masterSecretFunc = "gotls_mastersecret_stack"
	}

	p.Logger().Info().
		Str("elf_path", elfPath).
		Bool("register_abi", p.config.IsRegisterABI).
		Str("capture_mode", p.config.CaptureMode).
		Str("write_section", writeSection).
		Str("read_section", readSection).
		Msg("Setting up eBPF probes")

	// Initialize probes list and maps based on capture mode
	// Only one mode should be active at a time
	var probes []*manager.Probe
	var maps []*manager.Map

	// TEXT MODE: Capture TLS plaintext data (read/write)
	if p.config.CaptureMode == "text" {
		// Add write probe for crypto/tls.(*Conn).writeRecordLocked
		probes = append(probes, &manager.Probe{
			Section:          writeSection,
			EbpfFuncName:     writeFunc,
			AttachToFuncName: "crypto/tls.(*Conn).writeRecordLocked",
			BinaryPath:       elfPath,
			UAddress:         p.config.GoTlsWriteAddr,
		})

		p.Logger().Debug().
			Uint64("write_address", p.config.GoTlsWriteAddr).
			Msg("Added write probe")

		// Add read probes using ReadTlsAddrs array
		// Each address in ReadTlsAddrs represents a RET instruction offset for uretprobe
		if len(p.config.ReadTlsAddrs) > 0 {
			for i, addr := range p.config.ReadTlsAddrs {
				probes = append(probes, &manager.Probe{
					Section:          readSection,
					EbpfFuncName:     readFunc,
					AttachToFuncName: "crypto/tls.(*Conn).Read",
					BinaryPath:       elfPath,
					UAddress:         addr,
				})
				p.Logger().Debug().
					Int("index", i).
					Uint64("address", addr).
					Msg("Added read probe")
			}
		} else {
			// Fallback: if ReadTlsAddrs is empty, add a single probe at address 0
			p.Logger().Warn().Msg("ReadTlsAddrs is empty, using fallback read probe at address 0")
			probes = append(probes, &manager.Probe{
				Section:          readSection,
				EbpfFuncName:     readFunc,
				AttachToFuncName: "crypto/tls.(*Conn).Read",
				BinaryPath:       elfPath,
				UAddress:         0,
			})
		}

		// Initialize events map
		maps = append(maps, &manager.Map{Name: "events"})
	}

	// KEYLOG MODE: Capture TLS master secrets only
	if p.config.CaptureMode == "keylog" || p.config.CaptureMode == "key" {
		probes = append(probes, &manager.Probe{
			Section:          masterSecretSection,
			EbpfFuncName:     masterSecretFunc,
			AttachToFuncName: "crypto/tls.(*Config).writeKeyLog",
			BinaryPath:       elfPath,
			UAddress:         p.config.GoTlsMasterSecretAddr,
		})
		maps = append(maps, &manager.Map{Name: "mastersecret_go_events"})
		
		p.Logger().Debug().
			Uint64("master_secret_address", p.config.GoTlsMasterSecretAddr).
			Msg("Added master secret probe")
	}

	// PCAP/PCAPNG MODE: Capture network packets with TC + master secrets for DSB
	if p.config.CaptureMode == "pcap" || p.config.CaptureMode == "pcapng" {
		if p.config.Ifname == "" {
			return errors.NewConfigurationError("ifname is required for pcap mode", nil)
		}

		// Add ingress TC probe
		probes = append(probes, &manager.Probe{
			Section:          "classifier",
			EbpfFuncName:     "ingress_cls_func",
			Ifname:           p.config.Ifname,
			NetworkDirection: manager.Ingress,
		})

		// Add egress TC probe
		probes = append(probes, &manager.Probe{
			Section:          "classifier",
			EbpfFuncName:     "egress_cls_func",
			Ifname:           p.config.Ifname,
			NetworkDirection: manager.Egress,
		})

		// Add master secret probe for PCAPNG DSB (Decryption Secrets Block)
		probes = append(probes, &manager.Probe{
			Section:          masterSecretSection,
			EbpfFuncName:     masterSecretFunc,
			AttachToFuncName: "crypto/tls.(*Config).writeKeyLog",
			BinaryPath:       elfPath,
			UAddress:         p.config.GoTlsMasterSecretAddr,
		})

		// Add TC-related maps
		maps = append(maps, &manager.Map{Name: "skb_events"})
		maps = append(maps, &manager.Map{Name: "skb_data_buffer_heap"})
		maps = append(maps, &manager.Map{Name: "network_map"})
		
		// Add master secret events map for PCAPNG DSB
		maps = append(maps, &manager.Map{Name: "mastersecret_go_events"})

		p.Logger().Debug().
			Str("ifname", p.config.Ifname).
			Uint64("master_secret_address", p.config.GoTlsMasterSecretAddr).
			Msg("Added TC probes and master secret probe for pcap mode")
	}

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}

	return nil
}

// getManagerOptions returns eBPF manager options.
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
