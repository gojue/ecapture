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
	"io"
	"math"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/internal/output/writers"

	pkgebpf "github.com/gojue/ecapture/pkg/util/ebpf"

	"github.com/gojue/ecapture/internal/factory"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
	"github.com/gojue/ecapture/pkg/util/kernel"
)

const (
	GoTlsReadFunc         = "crypto/tls.(*Conn).Read"
	GoTlsWriteFunc        = "crypto/tls.(*Conn).writeRecordLocked"
	GoTlsMasterSecretFunc = "crypto/tls.(*Config).writeKeyLog"
)

// Probe represents the GoTLS probe
type Probe struct {
	*base.BaseProbe
	config           *Config
	bpfManager       *manager.Manager
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder // Maps configured in setupManager
	eventMaps        []*ebpf.Map
	closer           []io.Closer

	// File handles for different capture modes
	keylogFile *os.File
	pcapFile   *os.File
	PcapFilter string
	ifName     string
	ifIdex     int
}

// NewProbe creates a new GoTLS probe
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe:        base.NewBaseProbe(string(factory.ProbeTypeGoTLS)),
		eventFuncMaps:    make(map[*ebpf.Map]domain.EventDecoder),
		mapNameToDecoder: make(map[string]domain.EventDecoder),
		closer:           make([]io.Closer, 0),
	}, nil
}

// Initialize initializes the probe with the given configuration
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration) error {
	if err := p.BaseProbe.Initialize(ctx, cfg); err != nil {
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

	p.Logger().Info().Msg("GoTLS probe started successfully")
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

		p.Logger().Debug().Str("map", mapName).Str("decoder", fmt.Sprintf("%T", decoder)).Msg("Map found and decoder mapped")
		// Add to eventMaps and map the actual *ebpf.Map to decoder
		p.eventMaps = append(p.eventMaps, em)
		p.eventFuncMaps[em] = decoder
	}
	if len(p.eventFuncMaps) == 0 || len(p.mapNameToDecoder) != len(p.eventFuncMaps) {
		return errors.Wrap(errors.ErrCodeConfiguration, "no event maps found or decoder mapping mismatch", nil)
	}
	p.Logger().Info().
		Int("num_maps", len(p.eventMaps)).
		Int("num_decoders", len(p.eventFuncMaps)).
		Str("capture_mode", p.config.CaptureMode).
		Msg("Event maps retrieved and decoders mapped")

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
	for _, closer := range p.closer {
		if err := closer.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close resource")
		}
	}
	p.Logger().Debug().Msg("Calling BaseProbe.Close()")
	err := p.BaseProbe.Close()
	p.Logger().Debug().Msg("GoTLS probe closed")
	return err
}

// GetDecoder implements EventDecoder interface.
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	for i, m := range p.eventMaps {
		if m == em {
			if i == 0 || len(p.eventMaps) == 1 {
				return &GoTLSDataEvent{}, true
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
	var gotlsConf = p.config
	elfPath := gotlsConf.ElfPath
	if elfPath == "" {
		// Try to find Go binary in common locations
		// For now, we'll require ElfPath to be set
		return errors.NewConfigurationError("elf_path is required for GoTLS probe", nil)
	}

	var buildInfo = new(strings.Builder)
	for _, setting := range gotlsConf.BuildInfo.Settings {
		if setting.Value == "" {
			continue
		}
		buildInfo.WriteString(" ")
		buildInfo.WriteString(setting.Key)
		buildInfo.WriteString("=")
		buildInfo.WriteString(setting.Value)
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

	p.Logger().Debug().
		Str("capture_mode", p.config.CaptureMode).
		Msg("Setting up eBPF probes")

	var err error
	switch gotlsConf.CaptureMode {
	case handlers.ModeText:
		err = p.setupManagersText(writeSection, readSection, writeFunc, readFunc)
	case handlers.ModeKeylog, handlers.ModeKey:
		err = p.setupManagersKeyLog(masterSecretSection, masterSecretFunc)
	case handlers.ModePcap, handlers.ModePcapng:
		err = p.setupManagerPcapNG(masterSecretSection, masterSecretFunc)
		if err == nil && p.config.PcapFilter != "" {
			p.Logger().Info().Str("filter", p.config.PcapFilter).Msg("Applying BPF filter to TC probes")
			ebpfFuncs := []string{base.TcFuncNameIngress, base.TcFuncNameEgress}
			p.bpfManager.InstructionPatchers = pkgebpf.PrepareInsnPatchers(p.bpfManager, ebpfFuncs, p.config.PcapFilter)
		}
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

// setupManagersKeyLog configures the eBPF manager for keylog mode (GoTLS data capture)
func (p *Probe) setupManagersKeyLog(keySection, keyFunc string) error {
	var gotlsConf = p.config

	p.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			// gotls master secrets
			{
				Section:          keySection,
				EbpfFuncName:     keyFunc,
				AttachToFuncName: GoTlsMasterSecretFunc,
				BinaryPath:       gotlsConf.ElfPath,
				UID:              "uprobe_gotls_master_secret",
				UAddress:         gotlsConf.GoTlsMasterSecretAddr,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "mastersecret_go_events",
			},
		},
	}

	p.mapNameToDecoder["mastersecret_go_events"] = &masterSecretEventDecoder{}
	p.Logger().Info().Str("Section", keySection).Str("fn", keyFunc).Str("ATFN", GoTlsMasterSecretFunc).Uint64("uaddress", gotlsConf.GoTlsMasterSecretAddr).Send()
	p.Logger().Info().Str("Hook", GoTlsMasterSecretFunc).Str("section", keySection).
		Str("Func", keyFunc).Str("GoTlsMasterSecretAddr", fmt.Sprintf("%X", p.config.GoTlsMasterSecretAddr)).
		Msg("Added master secret probe")

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

	return nil
}

func (p *Probe) setupManagerPcapNG(keySection, keyFunc string) error {

	p.ifName = p.config.Ifname
	interf, err := net.InterfaceByName(p.ifName)
	if err != nil {
		return err
	}

	p.ifIdex = interf.Index

	pcapFilter := p.config.PcapFilter
	p.Logger().Info().Str("binrayPath", p.config.ElfPath).Str("IFname", p.ifName).Int("IFindex", p.ifIdex).
		Str("PcapFilter", pcapFilter).Str("hook", GoTlsMasterSecretFunc).
		Str("GoTlsMasterSecretAddr", fmt.Sprintf("%X", p.config.GoTlsMasterSecretAddr)).Send()

	var probes []*manager.Probe
	var maps []*manager.Map

	probes = []*manager.Probe{
		{
			Section:          "classifier/egress",
			EbpfFuncName:     base.TcFuncNameEgress,
			Ifname:           p.ifName,
			NetworkDirection: manager.Egress,
		},
		{
			Section:          "classifier/ingress",
			EbpfFuncName:     base.TcFuncNameIngress,
			Ifname:           p.ifName,
			NetworkDirection: manager.Ingress,
		},
		// --------------------------------------------------

		// gotls master secrets
		{
			Section:          keySection,
			EbpfFuncName:     keyFunc,
			AttachToFuncName: GoTlsMasterSecretFunc,
			BinaryPath:       p.config.ElfPath,
			UID:              "uprobe_gotls_master_secret",
			UAddress:         p.config.GoTlsMasterSecretAddr,
		},
	}

	maps = []*manager.Map{
		{
			Name: "mastersecret_go_events",
		},
		{
			Name: "skb_events",
		},
	}

	// Add TC-related maps for network packet capture
	p.mapNameToDecoder["skb_events"] = &packetEventDecoder{}
	p.mapNameToDecoder["mastersecret_go_events"] = &masterSecretEventDecoder{}

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
		// Note: keylogWriter will be closed through keylogHandler.Close() when dispatcher closes
		// Don't add it to p.closer to avoid double-close
		p.Logger().Info().Str("Writer", keylogWriter.Name()).Msg("Keylog handler registered for pcapng mode")
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

	pcapHandler, err := handlers.NewPcapHandler(pcapWriter, p.config.Ifname, p.config.PcapFilter, p.Logger())
	if err != nil {
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to create pcap handler: %w", err)
	}

	if err := p.BaseProbe.Dispatcher().Register(pcapHandler); err != nil {
		_ = pcapHandler.Close()
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to register pcap handler: %w", err)
	}
	// Note: pcapWriter will be closed through pcapHandler.Close() when dispatcher closes
	// Don't add it to p.closer to avoid double-close
	//p.Logger().Info().Str("Writer", pcapWriter.Name()).Msg("Pcap handler registered")

	// Pcapng 的 Keylog writer
	pcapKeylogWriter := writers.NewPcapKeylogWriter(pcapHandler.PcapWriter())
	pcapKeylogHandler := handlers.NewKeylogHandler(pcapKeylogWriter)
	if err := p.BaseProbe.Dispatcher().Register(pcapKeylogHandler); err != nil {
		_ = pcapHandler.Close()
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to register pcapkeylog handler: %w", err)
	}
	// Note: pcapKeylogWriter will be closed through pcapKeylogHandler.Close()
	// Don't add it to p.closer to avoid double-close
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

func (p *Probe) setupManagersText(sec, readSec, fn, readFn string) error {
	p.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: GoTlsWriteFunc,
				BinaryPath:       p.config.ElfPath,
				UAddress:         p.config.GoTlsWriteAddr,
			},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}
	p.mapNameToDecoder["events"] = &tlsDataEventDecoder{probe: p}

	readOffsets := p.config.ReadTlsAddrs
	//p.bpfManager.Probes = []*manager.Probe{}
	p.Logger().Info().Str("write_section", sec).
		Str("read_section", readSec).Str("function", readFn).
		Str("offsets", fmt.Sprintf("%v", readOffsets)).Msg("golang uretprobe added.")
	for _, v := range readOffsets {
		var uid = fmt.Sprintf("%s_%X", readFn, v)
		p.bpfManager.Probes = append(p.bpfManager.Probes, &manager.Probe{
			Section:          readSec,
			EbpfFuncName:     readFn,
			AttachToFuncName: GoTlsReadFunc,
			BinaryPath:       p.config.ElfPath,
			UAddress:         uint64(v),
			UID:              uid,
		})
	}

	return nil
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

// tlsDataEventDecoder implements domain.EventDecoder for TLS data events
type tlsDataEventDecoder struct {
	probe *Probe
}

func (d *tlsDataEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &GoTLSDataEvent{}
	fmt.Println("Decoding TLSDataEvent from bytes, data length:", len(data))
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *tlsDataEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &GoTLSDataEvent{}, true
}

// masterSecretEventDecoder implements domain.EventDecoder for master secret events
type masterSecretEventDecoder struct {
	//probe *Probe
}

func (d *masterSecretEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &MasterSecretEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
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
