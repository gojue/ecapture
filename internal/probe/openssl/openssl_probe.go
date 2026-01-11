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

	"github.com/gojue/ecapture/internal/events"
	"github.com/gojue/ecapture/internal/logger"

	"github.com/gojue/ecapture/internal/output/writers"

	"github.com/gojue/ecapture/internal/factory"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
	"github.com/gojue/ecapture/pkg/util/kernel"
)

// Probe implements the OpenSSL TLS tracing probe.
// Supports Text mode, Keylog mode, and Pcap mode.
type Probe struct {
	*base.BaseProbe
	config           *Config
	bpfManager       *manager.Manager
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder // Maps configured in setupManager
	eventMaps        []*ebpf.Map
	output           io.Writer
}

// NewProbe creates a new OpenSSL probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe:        base.NewBaseProbe(string(factory.ProbeTypeOpenSSL)),
		eventFuncMaps:    make(map[*ebpf.Map]domain.EventDecoder),
		mapNameToDecoder: make(map[string]domain.EventDecoder),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration) error {
	if err := p.BaseProbe.Initialize(ctx, cfg); err != nil {
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

	keylogFile := opensslConfig.GetKeylogFile()
	if keylogFile == "" {
		return fmt.Errorf("keylog mode requires keylog file path")
	}

	// Log initialization
	p.Logger().Info().
		Str("openssl_path", opensslConfig.OpensslPath).
		Str("ssl_version", opensslConfig.SslVersion).
		Bool("is_boringssl", opensslConfig.IsBoringSSL).
		Str("capture_mode", opensslConfig.CaptureMode).
		Msg("OpenSSL probe initialized")

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

	// Retrieve eBPF maps and associate with decoders (configured in setupManager)
	if err := p.retrieveEventMaps(); err != nil {
		return err
	}

	// Start event readers for all configured maps
	for em, decoder := range p.eventFuncMaps {
		if err := p.StartPerfEventReader(em, decoder); err != nil {
			return err
		}
		p.Logger().Debug().
			Str("map", em.String()).
			Msg("Started perf event reader")
	}

	p.Logger().Info().Msg("OpenSSL probe started successfully")
	return nil
}

// retrieveEventMaps retrieves eBPF maps from the manager and creates eventFuncMaps.
// The decoder mapping by name (mapNameToDecoder) is already configured in setupManager().
func (p *Probe) retrieveEventMaps() error {
	// Retrieve all maps that were configured in setupManager
	for mapName, decoder := range p.mapNameToDecoder {
		em, found, err := p.bpfManager.GetMap(mapName)
		if err != nil {
			return errors.Wrap(errors.ErrCodeEBPFMapAccess, fmt.Sprintf("failed to get %s map", mapName), err)
		}
		if !found {
			// Some maps might not be found (edge case)
			p.Logger().Warn().Str("map", mapName).Msg("Map not found but was configured")
			continue
		}

		// Add to eventMaps and map the actual *ebpf.Map to decoder
		p.eventMaps = append(p.eventMaps, em)
		p.eventFuncMaps[em] = decoder
	}

	p.Logger().Info().
		Int("num_maps", len(p.eventMaps)).
		Int("num_decoders", len(p.eventFuncMaps)).
		Str("capture_mode", p.config.CaptureMode).
		Msg("Event maps retrieved and decoders mapped")

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

	p.Logger().Debug().Msg("Calling BaseProbe.Close()")
	err := p.BaseProbe.Close()
	p.Logger().Debug().Msg("OpenSSL probe closed")
	return err
}

// SetOutput sets the output writer for the probe (for testing purposes).
func (p *Probe) SetOutput(w io.Writer) {
	p.output = w
}

func (p *Probe) setupManagerText() error {
	opensslPath := p.config.OpensslPath
	if opensslPath == "" {
		return errors.NewConfigurationError("openssl_path is required for OpenSSL probe", nil)
	}

	var probes []*manager.Probe
	var maps []*manager.Map
	// Base TLS events map (used by all modes for SSL_read/SSL_write data)
	maps = append(maps, &manager.Map{Name: "tls_events"})
	p.mapNameToDecoder["tls_events"] = &tlsEventDecoder{probe: p}

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

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}

	// Create internal logger wrapper from zerolog
	log := logger.New(os.Stdout, p.config.GetDebug())

	// Create dispatcher
	dispatcher := events.NewDispatcher(log)
	// Create writer factory for creating output writers
	writerFactory := writers.NewWriterFactory()

	// Configure rotation for file writers (from --eventroratesize and --eventroratetime flags)
	var rotateConfig *writers.RotateConfig

	// Create output writer based on eventAddr (or stdout if empty)
	var textWriter writers.OutputWriter
	var err error
	var eventAddr = p.config.GetEventCollectorAddr()
	if eventAddr == "" || eventAddr == "stdout" {
		textWriter = writers.NewStdoutWriter()
	} else {
		textWriter, err = writerFactory.CreateWriter(eventAddr, rotateConfig)
		if err != nil {
			return fmt.Errorf("failed to create text output writer: %w", err)
		}
	}
	p.Logger().Info().Str("eventAddr", eventAddr).Str("LoggerAddr", p.config.LoggerAddr).Msg("Text output writer created")
	textHandler := handlers.NewTextHandler(textWriter, p.config.IsHex)
	if err := dispatcher.Register(textHandler); err != nil {
		_ = textWriter.Close()
		return fmt.Errorf("failed to register text handler: %w", err)
	}
	p.BaseProbe.SetDispatcher(dispatcher)
	return nil
}

func (p *Probe) setupManagerPcapNG() error {
	opensslPath := p.config.OpensslPath
	var probes []*manager.Probe
	var maps []*manager.Map
	// PCAP mode: TC probes for network capture + master secret probe
	// Validate network interface is configured
	if p.config.Ifname == "" {
		return errors.NewConfigurationError("ifname is required for pcap mode", nil)
	}

	// Master secret events map for keylog in pcapng
	maps = append(maps, &manager.Map{Name: "mastersecret_events"})
	p.mapNameToDecoder["mastersecret_events"] = &masterSecretEventDecoder{probe: p}

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
	p.mapNameToDecoder["skb_events"] = &packetEventDecoder{}

	// These maps don't need decoders (used internally by eBPF)
	maps = append(maps, &manager.Map{Name: "skb_data_buffer_heap"})
	maps = append(maps, &manager.Map{Name: "network_map"})

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

	// Create writer factory for creating output writers
	writerFactory := writers.NewWriterFactory()
	// Create file writer for keylog
	keylogWriter, err := writerFactory.CreateWriter(p.config.GetKeylogFile(), &writers.RotateConfig{false, 0, 300})
	if err != nil {
		p.Logger().Warn().Err(err).Str("keylog file", p.config.GetKeylogFile()).Msg("Failed to create keylog handler, continuing without keylog")
	} else {
		keylogHandler := handlers.NewKeylogHandler(keylogWriter)
		if err := p.BaseProbe.Dispatcher().Register(keylogHandler); err != nil {
			_ = keylogWriter.Close()
			return fmt.Errorf("failed to register keylog handler: %w", err)
		}
	}

	pcapFile := p.config.GetPcapFile()
	if pcapFile == "" {
		return fmt.Errorf("pcap mode requires pcap file path")
	}

	// Create file writer for pcap (use O_TRUNC to overwrite existing file)
	// Note: pcap files should not use rotation
	pcapWriter, err := writers.NewFileWriter(writers.FileWriterConfig{
		Path:       pcapFile,
		BufferSize: 65536, // 64KB buffer for better pcap write performance
	})
	if err != nil {
		return fmt.Errorf("failed to create pcap writer: %w", err)
	}

	pcapHandler, err := handlers.NewPcapHandler(pcapWriter)
	if err != nil {
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to create pcap handler: %w", err)
	}

	if err := p.BaseProbe.Dispatcher().Register(pcapHandler); err != nil {
		_ = pcapHandler.Close()
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to register pcap handler: %w", err)
	}

	// Pcapng 的 Keylog writer
	pcapKeylogWriter := handlers.NewPcapKeylogWriter(pcapHandler.PcapWriter())
	pcapKeylogHandler := handlers.NewKeylogHandler(pcapKeylogWriter)
	if err := p.BaseProbe.Dispatcher().Register(pcapKeylogHandler); err != nil {
		_ = pcapHandler.Close()
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to register pcapkeylog handler: %w", err)
	}
	p.Logger().Info().Str("pcap_file", pcapFile).Msg("Pcap handler registered")
	p.Logger().Debug().
		Str("ifname", p.config.Ifname).
		Msg("Added TC probes, SSL probes, and master secret probe for pcap mode")
	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}
	return nil
}

func (p *Probe) setupManagerKeyLog() error {
	opensslPath := p.config.OpensslPath
	var probes []*manager.Probe
	var maps []*manager.Map
	// KEYLOG mode: Master secret extraction probes
	maps = append(maps, &manager.Map{Name: "mastersecret_events"})
	p.mapNameToDecoder["mastersecret_events"] = &masterSecretEventDecoder{probe: p}

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
	// Create writer factory for creating output writers
	writerFactory := writers.NewWriterFactory()

	// Create file writer for keylog
	keylogWriter, err := writerFactory.CreateWriter(p.config.GetKeylogFile(), &writers.RotateConfig{false, 0, 300})
	if err != nil {
		return fmt.Errorf("failed to create keylog writer: %w", err)
	}

	keylogHandler := handlers.NewKeylogHandler(keylogWriter)
	if err := p.BaseProbe.Dispatcher().Register(keylogHandler); err != nil {
		_ = keylogWriter.Close()
		return fmt.Errorf("failed to register keylog handler: %w", err)
	}
	p.Logger().Info().Str("keylog_file", p.config.GetKeylogFile()).Msg("Keylog handler registered")

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}
	return nil
}

// setupManager configures the eBPF manager with probes and maps.
// This method also configures decoder mappings by map name (mapNameToDecoder).
// The actual *ebpf.Map to decoder mapping (eventFuncMaps) is created in retrieveEventMaps().
func (p *Probe) setupManager() error {
	var err error
	// Mode-specific probe and map setup
	switch p.config.CaptureMode {
	case handlers.ModeText:
		err = p.setupManagerText()
	case handlers.ModeKeylog, handlers.ModeKey:
		err = p.setupManagerKeyLog()
	case handlers.ModePcap, handlers.ModePcapng:
		err = p.setupManagerPcapNG()
	}
	if err != nil {
		return err
	}
	p.Logger().Info().
		Str("openssl_path", p.config.OpensslPath).
		Str("capture_mode", p.config.CaptureMode).
		Int("num_probes", len(p.bpfManager.Probes)).
		Int("num_maps", len(p.bpfManager.Maps)).
		Msg("Setting up eBPF probes")

	for _, e := range p.bpfManager.Probes {
		p.Logger().Debug().Str("probe", e.AttachToFuncName).Msg("Configured eBPF probe")
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
		kv, _ := kernel.HostVersion()
		kernelLess52 := uint64(0)
		if kv < kernel.VersionCode(5, 2, 0) {
			kernelLess52 = 1
		}

		opts.ConstantEditors = []manager.ConstantEditor{
			{Name: "target_pid", Value: p.config.GetPid()},
			{Name: "target_uid", Value: p.config.GetUid()},
			{Name: "less52", Value: kernelLess52},
		}
	}

	return opts
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

// tlsEventDecoder implements domain.EventDecoder for TLS data events
type tlsEventDecoder struct {
	probe *Probe
}

func (d *tlsEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *tlsEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &Event{}, true
}

// masterSecretEventDecoder implements domain.EventDecoder for master secret events
type masterSecretEventDecoder struct {
	probe *Probe
}

func (d *masterSecretEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &MasterSecretEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}

	// Event will be dispatched to registered handlers:
	// - KeylogHandler: writes master secret to keylog file
	// - MasterSecretInfoHandler: prints summary to stdout
	return event, nil
}

func (d *masterSecretEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &MasterSecretEvent{}, true
}

// packetEventDecoder implements domain.EventDecoder for packet events
type packetEventDecoder struct{}

func (d *packetEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &PacketEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *packetEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &PacketEvent{}, true
}
