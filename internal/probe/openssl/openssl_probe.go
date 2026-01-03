// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package openssl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Probe implements the OpenSSL TLS tracing probe.
// Supports Text mode, Keylog mode, and Pcap mode.
type Probe struct {
	*base.BaseProbe
	config     *Config
	bpfManager *manager.Manager
	eventMaps  []*ebpf.Map
	output     io.Writer
	keylogFile *os.File
	pcapFile   *os.File
}

// NewProbe creates a new OpenSSL probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe: base.NewBaseProbe("openssl"),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	// Type assert to OpenSSL-specific config
	opensslConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for openssl probe", nil)
	}
	p.config = opensslConfig

	// Validate that the detected version is supported
	if !p.config.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported OpenSSL version: %s", p.config.SslVersion))
	}

	// Open output files based on capture mode
	if err := p.openOutputFiles(); err != nil {
		return err
	}

	// Log initialization with file paths
	logEvent := p.Logger().Info().
		Str("openssl_path", opensslConfig.OpensslPath).
		Str("ssl_version", opensslConfig.SslVersion).
		Bool("is_boringssl", opensslConfig.IsBoringSSL).
		Str("capture_mode", opensslConfig.CaptureMode)
	
	// Add file paths to log based on mode
	if opensslConfig.CaptureMode == "keylog" || opensslConfig.CaptureMode == "key" {
		if opensslConfig.KeylogFile != "" {
			logEvent = logEvent.Str("keylog_file", opensslConfig.KeylogFile)
		}
	} else if opensslConfig.CaptureMode == "pcap" {
		if opensslConfig.PcapFile != "" {
			logEvent = logEvent.Str("pcap_file", opensslConfig.PcapFile)
		}
		if opensslConfig.KeylogFile != "" {
			logEvent = logEvent.Str("keylog_file", opensslConfig.KeylogFile)
		}
		if opensslConfig.Ifname != "" {
			logEvent = logEvent.Str("ifname", opensslConfig.Ifname)
		}
	}
	
	logEvent.Msg("OpenSSL probe initialized")

	return nil
}

// openOutputFiles opens output files based on capture mode
func (p *Probe) openOutputFiles() error {
	// Normalize capture mode: treat "pcapng" as "pcap"
	if p.config.CaptureMode == "pcapng" {
		p.config.CaptureMode = "pcap"
	}

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

	case "pcap":
		// PCAP mode requires pcap file for storing TC probe network packets
		if p.config.PcapFile == "" {
			return errors.NewConfigurationError("pcap_file is required for pcap mode", nil)
		}
		file, err := os.OpenFile(p.config.PcapFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return errors.NewConfigurationError("failed to open pcap file", err)
		}
		p.pcapFile = file

		// For pcap mode, optionally open keylog file if specified
		// Master secrets can be embedded in PCAPNG DSB blocks or written to separate keylog
		if p.config.KeylogFile != "" {
			keylogFile, err := os.OpenFile(p.config.KeylogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				p.Logger().Warn().Err(err).Msg("Failed to open keylog file for pcap mode, will embed in DSB only")
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

// Start begins the OpenSSL probe operation.
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
		return errors.NewEBPFLoadError("openssl manager init", err)
	}

	// Start eBPF manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("openssl manager start", err)
	}

	// Get event maps based on capture mode
	tlsEventsMap, found, err := p.bpfManager.GetMap("tls_events")
	if err != nil {
		return errors.Wrap(errors.ErrCodeEBPFMapAccess, "failed to get tls_events map", err)
	}
	if !found {
		return errors.NewResourceNotFoundError("eBPF map: tls_events")
	}

	// Get master secret events map if in keylog or pcap mode
	var masterSecretMap *ebpf.Map
	if p.config.CaptureMode == "keylog" || p.config.CaptureMode == "key" || p.config.CaptureMode == "pcap" {
		masterSecretMap, found, err = p.bpfManager.GetMap("mastersecret_events")
		if err != nil {
			return errors.Wrap(errors.ErrCodeEBPFMapAccess, "failed to get mastersecret_events map", err)
		}
		if !found {
			p.Logger().Warn().Msg("Master secret map not found, keylog capture may be incomplete")
		}
	}

	// Store event maps
	if masterSecretMap != nil {
		p.eventMaps = []*ebpf.Map{tlsEventsMap, masterSecretMap}
	} else {
		p.eventMaps = []*ebpf.Map{tlsEventsMap}
	}

	// Start event readers
	if err := p.StartPerfEventReader(tlsEventsMap, p); err != nil {
		return err
	}

	if masterSecretMap != nil {
		if err := p.StartPerfEventReader(masterSecretMap, p); err != nil {
			return err
		}
	}

	p.Logger().Info().Msg("OpenSSL probe started successfully")
	return nil
}

// Stop gracefully stops the probe.
func (p *Probe) Stop(ctx context.Context) error {
	// Stop event readers are handled by BaseProbe
	return p.BaseProbe.Stop(ctx)
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	if p.eventMaps == nil {
		return []*ebpf.Map{}
	}
	return p.eventMaps
}

// Close releases all probe resources.
func (p *Probe) Close() error {
	p.Logger().Debug().Msg("Closing OpenSSL probe")
	
	// Stop eBPF manager
	if p.bpfManager != nil {
		p.Logger().Debug().Msg("Stopping eBPF manager")
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to stop eBPF manager")
		}
		p.Logger().Debug().Msg("eBPF manager stopped")
	}

	// Close file handles
	if p.keylogFile != nil {
		p.Logger().Debug().Msg("Closing keylog file")
		if err := p.keylogFile.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close keylog file")
		}
		p.keylogFile = nil
	}

	if p.pcapFile != nil {
		p.Logger().Debug().Msg("Closing pcap file")
		if err := p.pcapFile.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close pcap file")
		}
		p.pcapFile = nil
	}

	p.Logger().Debug().Msg("Calling BaseProbe.Close()")
	err := p.BaseProbe.Close()
	p.Logger().Debug().Msg("OpenSSL probe closed")
	return err
}

// Decode implements EventDecoder interface.
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
	// Handle nil map (for testing)
	if em == nil {
		// Try to decode as TLS data event
		event := &Event{}
		if err := event.DecodeFromBytes(data); err != nil {
			return nil, err
		}
		if err := event.Validate(); err != nil {
			return nil, err
		}
		return event, nil
	}

	// Determine event type based on map
	for i, m := range p.eventMaps {
		if m == em {
			// First map is always tls_events (TLS data)
			if i == 0 || len(p.eventMaps) == 1 {
				event := &Event{}
				if err := event.DecodeFromBytes(data); err != nil {
					return nil, err
				}
				if err := event.Validate(); err != nil {
					return nil, err
				}
				return event, nil
			}
			// Second map is mastersecret_events (if exists)
			if i == 1 {
				event := &MasterSecretEvent{}
				if err := event.DecodeFromBytes(data); err != nil {
					return nil, err
				}
				if err := event.Validate(); err != nil {
					return nil, err
				}
				// Write master secret to keylog file if in keylog or pcap mode
				if err := p.writeMasterSecretToFile(event); err != nil {
					p.Logger().Warn().Err(err).Msg("Failed to write master secret to file")
				}
				return event, nil
			}
		}
	}
	return nil, fmt.Errorf("unknown eBPF map")
}

// writeMasterSecretToFile writes a master secret event to the appropriate output file
func (p *Probe) writeMasterSecretToFile(event *MasterSecretEvent) error {
	if event == nil {
		return nil
	}

	// Only write to keylog file in keylog or pcap mode
	if p.config.CaptureMode != "keylog" && p.config.CaptureMode != "key" &&
		p.config.CaptureMode != "pcap" {
		return nil
	}

	// Ensure we have a file to write to
	var file *os.File
	if p.config.CaptureMode == "keylog" || p.config.CaptureMode == "key" {
		file = p.keylogFile
	} else if p.config.CaptureMode == "pcap" {
		// For pcap mode, we also write to keylog file (DSB block handling)
		// If keylogFile is set, use it; otherwise, pcapFile will handle DSB internally
		file = p.keylogFile
		if file == nil {
			// TODO: In pcapng mode, master secrets should be written to DSB blocks
			// For now, we'll just log them
			p.Logger().Debug().
				Int32("version", event.Version).
				Msg("Master secret event (will be added to PCAPNG DSB)")
			return nil
		}
	}

	if file == nil {
		return fmt.Errorf("keylog file not open")
	}

	// Write master secrets in NSS SSLKEYLOGFILE format
	// Format: LABEL CLIENTRANDOM SECRET
	// This follows the format used by Wireshark
	version := event.GetVersion()
	clientRandom := event.GetClientRandom()

	// TLS 1.2 and earlier use CLIENT_RANDOM format
	if version <= 0x0303 { // TLS 1.2 = 0x0303
		masterKey := event.GetMasterKey()
		
		// Skip if client random or master key are all zeros
		if isZeroBytes(clientRandom) || isZeroBytes(masterKey) {
			p.Logger().Debug().Msg("Skipping TLS 1.2 master secret with zero values")
			return nil
		}
		
		line := fmt.Sprintf("CLIENT_RANDOM %x %x\n",
			clientRandom[:handlers.Ssl3RandomSize],
			masterKey[:handlers.MasterSecretMaxLen])
		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("failed to write keylog entry: %w", err)
		}
		// Sync to ensure data is written
		if err := file.Sync(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to sync keylog file")
		}
		return nil
	}

	// TLS 1.3 uses multiple secret types
	clientRandomHex := fmt.Sprintf("%x", clientRandom[:handlers.Ssl3RandomSize])

	// Write each TLS 1.3 secret type if available
	// Note: OpenSSL's client_app_traffic_secret and server_app_traffic_secret fields
	// may contain handshake traffic secrets during the handshake phase,
	// and application traffic secrets after the handshake completes.
	// We output both labels to support decryption at different stages.
	secrets := []struct {
		label string
		data  []byte
	}{
		// Handshake traffic secrets (used during TLS handshake)
		{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", event.GetClientAppTrafficSecret()},
		{"SERVER_HANDSHAKE_TRAFFIC_SECRET", event.GetServerAppTrafficSecret()},
		// Application traffic secrets (used after handshake completion)
		{"CLIENT_TRAFFIC_SECRET_0", event.GetClientAppTrafficSecret()},
		{"SERVER_TRAFFIC_SECRET_0", event.GetServerAppTrafficSecret()},
		// Exporter master secret
		{"EXPORTER_SECRET", event.GetExporterMasterSecret()},
	}

	for _, secret := range secrets {
		if len(secret.data) == 0 || isZeroBytes(secret.data) {
			continue // Skip empty or zero secrets
		}

		line := fmt.Sprintf("%s %s %x\n", secret.label, clientRandomHex, secret.data)
		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("failed to write %s: %w", secret.label, err)
		}
	}

	// Sync to ensure data is written
	if err := file.Sync(); err != nil {
		p.Logger().Warn().Err(err).Msg("Failed to sync keylog file")
	}

	return nil
}

// isZeroBytes checks if a byte slice contains only zeros.
func isZeroBytes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// SetOutput sets the output writer for the probe (for testing purposes).
func (p *Probe) SetOutput(w io.Writer) {
	p.output = w
}

// GetDecoder implements EventDecoder interface.
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	// Handle nil map (for testing)
	if em == nil {
		return &Event{}, true
	}

	for i, m := range p.eventMaps {
		if m == em {
			if i == 0 || len(p.eventMaps) == 1 {
				return &Event{}, true
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
	opensslPath := p.config.OpensslPath
	if opensslPath == "" {
		return errors.NewConfigurationError("openssl_path is required for OpenSSL probe", nil)
	}

	var probes []*manager.Probe
	var maps []*manager.Map

	// Base TLS events map (used by most modes)
	maps = append(maps, &manager.Map{Name: "tls_events"})

	// Mode-specific probe and map setup
	switch p.config.CaptureMode {
	case "text":
		// TEXT mode: Only SSL_read/SSL_write probes for data capture
		probes = append(probes,
			&manager.Probe{
				Section:          "uprobe/SSL_write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       opensslPath,
			},
			&manager.Probe{
				Section:          "uretprobe/SSL_write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       opensslPath,
			},
			&manager.Probe{
				Section:          "uprobe/SSL_read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       opensslPath,
			},
			&manager.Probe{
				Section:          "uretprobe/SSL_read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       opensslPath,
			},
		)

	case "keylog", "key":
		// KEYLOG mode: Master secret extraction probes
		maps = append(maps, &manager.Map{Name: "mastersecret_events"})

		// Add master secret extraction probes based on OpenSSL version
		if p.config.IsBoringSSL {
			// BoringSSL uses different function names
			probes = append(probes,
				&manager.Probe{
					Section:          "uprobe/SSL_get_wbio",
					EbpfFuncName:     "probe_ssl_master_key",
					AttachToFuncName: "SSL_get_wbio",
					BinaryPath:       opensslPath,
				},
			)
		} else {
			// OpenSSL 1.1.1+ and 3.x
			probes = append(probes,
				&manager.Probe{
					Section:          "uprobe/SSL_do_handshake",
					EbpfFuncName:     "probe_ssl_master_key",
					AttachToFuncName: "SSL_do_handshake",
					BinaryPath:       opensslPath,
				},
			)
		}

	case "pcap":
		// PCAP mode: TC probes for network capture + master secret probe
		// Validate network interface is configured
		if p.config.Ifname == "" {
			return errors.NewConfigurationError("ifname is required for pcap mode", nil)
		}
		
		maps = append(maps, &manager.Map{Name: "mastersecret_events"})
		
		// Add TC (Traffic Control) classifier probes for packet capture
		// Ingress: packets coming into the network interface
		probes = append(probes,
			&manager.Probe{
				Section:          "classifier",
				EbpfFuncName:     "ingress_cls_func",
				Ifname:           p.config.Ifname,
				NetworkDirection: manager.Ingress,
			},
		)
		
		// Egress: packets going out of the network interface
		probes = append(probes,
			&manager.Probe{
				Section:          "classifier",
				EbpfFuncName:     "egress_cls_func",
				Ifname:           p.config.Ifname,
				NetworkDirection: manager.Egress,
			},
		)
		
		// Add TC-related maps for network packet capture
		maps = append(maps, &manager.Map{Name: "skb_events"})
		maps = append(maps, &manager.Map{Name: "skb_data_buffer_heap"})
		maps = append(maps, &manager.Map{Name: "network_map"})

		// Add SSL_read/SSL_write for connection tracking
		probes = append(probes,
			&manager.Probe{
				Section:          "uprobe/SSL_write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       opensslPath,
			},
			&manager.Probe{
				Section:          "uretprobe/SSL_write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       opensslPath,
			},
			&manager.Probe{
				Section:          "uprobe/SSL_read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       opensslPath,
			},
			&manager.Probe{
				Section:          "uretprobe/SSL_read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       opensslPath,
			},
		)

		// Add master secret extraction
		if p.config.IsBoringSSL {
			probes = append(probes,
				&manager.Probe{
					Section:          "uprobe/SSL_get_wbio",
					EbpfFuncName:     "probe_ssl_master_key",
					AttachToFuncName: "SSL_get_wbio",
					BinaryPath:       opensslPath,
				},
			)
		} else {
			probes = append(probes,
				&manager.Probe{
					Section:          "uprobe/SSL_do_handshake",
					EbpfFuncName:     "probe_ssl_master_key",
					AttachToFuncName: "SSL_do_handshake",
					BinaryPath:       opensslPath,
				},
			)
		}
		
		p.Logger().Debug().
			Str("ifname", p.config.Ifname).
			Msg("Added TC probes, SSL probes, and master secret probe for pcap mode")
	}

	p.Logger().Info().
		Str("openssl_path", opensslPath).
		Str("capture_mode", p.config.CaptureMode).
		Int("num_probes", len(probes)).
		Int("num_maps", len(maps)).
		Msg("Setting up eBPF probes")

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
