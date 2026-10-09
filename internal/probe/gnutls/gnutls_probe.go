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

package gnutls

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/v2/assets"
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/factory"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
	pkgebpf "github.com/gojue/ecapture/v2/pkg/util/ebpf"
	"github.com/gojue/ecapture/v2/pkg/util/kernel"
)

type Probe struct {
	*base.BaseProbe
	config           *Config
	bpfManager       *manager.Manager
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder
	eventMaps        []*ebpf.Map
}

func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe:        base.NewBaseProbe(string(factory.ProbeTypeGnuTLS)),
		eventFuncMaps:    make(map[*ebpf.Map]domain.EventDecoder),
		mapNameToDecoder: make(map[string]domain.EventDecoder),
		eventMaps:        make([]*ebpf.Map, 0, 2),
	}, nil
}

func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration) error {
	if err := p.BaseProbe.Initialize(ctx, cfg); err != nil {
		return err
	}

	gnutlsConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for gnutls probe", nil)
	}
	p.config = gnutlsConfig
	if !p.config.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported GnuTLS version: %s", p.config.GnuVersion))
	}

	p.Logger().Info().
		Str("gnutls_path", gnutlsConfig.GnutlsPath).
		Str("gnutls_version", gnutlsConfig.GnuVersion).
		Str("capture_mode", gnutlsConfig.CaptureMode).
		Msg("GnuTLS probe initialized")
	return nil
}

func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	bpfFileName := p.BaseProbe.GetBPFName("bytecode/" + p.config.GetBPFFileName())
	p.Logger().Info().Str("file", bpfFileName).Msg("Loading eBPF bytecode")
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return errors.NewEBPFLoadError(bpfFileName, err)
	}

	if err := p.setupManager(); err != nil {
		return err
	}
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), p.getManagerOptions()); err != nil {
		return errors.NewEBPFLoadError("gnutls manager init", err)
	}
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("gnutls manager start", err)
	}
	if err := p.retrieveEventMaps(); err != nil {
		return err
	}

	for em, decoder := range p.eventFuncMaps {
		if err := p.StartPerfEventReader(em, decoder); err != nil {
			return err
		}
		p.Logger().Debug().Str("map", em.String()).Msg("Started perf event reader")
	}

	p.Logger().Info().Msg("GnuTLS probe started successfully")
	return nil
}

func (p *Probe) retrieveEventMaps() error {
	for mapName, decoder := range p.mapNameToDecoder {
		em, found, err := p.bpfManager.GetMap(mapName)
		if err != nil {
			return errors.Wrap(errors.ErrCodeEBPFMapAccess,
				fmt.Sprintf("failed to get %s map", mapName), err)
		}
		if !found {
			return errors.New(errors.ErrCodeEBPFMapAccess,
				fmt.Sprintf("configured event map not found: %s", mapName))
		}
		p.eventMaps = append(p.eventMaps, em)
		p.eventFuncMaps[em] = decoder
	}
	if len(p.eventFuncMaps) == 0 || len(p.eventFuncMaps) != len(p.mapNameToDecoder) {
		return errors.New(errors.ErrCodeConfiguration,
			"no GnuTLS event maps found or decoder mapping mismatch")
	}

	p.Logger().Info().
		Int("num_maps", len(p.eventMaps)).
		Int("num_decoders", len(p.eventFuncMaps)).
		Str("capture_mode", p.config.CaptureMode).
		Msg("Event maps retrieved and decoders mapped")
	return nil
}

func (p *Probe) Stop(ctx context.Context) error {
	return p.BaseProbe.Stop(ctx)
}

func (p *Probe) Events() []*ebpf.Map {
	if p.eventMaps == nil {
		return []*ebpf.Map{}
	}
	return p.eventMaps
}

func (p *Probe) Close() error {
	if p.bpfManager != nil {
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to stop eBPF manager")
		}
	}
	if p.BaseProbe == nil {
		return nil
	}
	return p.BaseProbe.Close()
}

func (p *Probe) setupManager() error {
	p.eventMaps = p.eventMaps[:0]
	p.eventFuncMaps = make(map[*ebpf.Map]domain.EventDecoder)
	p.mapNameToDecoder = make(map[string]domain.EventDecoder)

	var err error
	switch p.config.CaptureMode {
	case handlers.ModeText:
		err = p.setupManagerText()
	case handlers.ModeKeylog, handlers.ModeKey:
		err = p.setupManagerKeylog()
	case handlers.ModePcap, handlers.ModePcapng:
		err = p.setupManagerPcapNG()
		if err == nil && p.config.PcapFilter != "" {
			functions := []string{base.TcFuncNameIngress, base.TcFuncNameEgress}
			p.bpfManager.InstructionPatchers = pkgebpf.PrepareInsnPatchers(
				p.bpfManager, functions, p.config.PcapFilter)
		}
	default:
		err = errors.NewConfigurationError(
			fmt.Sprintf("unsupported GnuTLS capture mode: %s", p.config.CaptureMode), nil)
	}
	if err != nil {
		return err
	}

	p.Logger().Info().
		Str("gnutls_path", p.config.GnutlsPath).
		Str("capture_mode", p.config.CaptureMode).
		Int("num_probes", len(p.bpfManager.Probes)).
		Int("num_maps", len(p.bpfManager.Maps)).
		Msg("Setting up GnuTLS eBPF probes")
	return nil
}

func (p *Probe) setupManagerText() error {
	path := p.config.GnutlsPath
	if path == "" {
		return errors.NewConfigurationError("gnutls path is required", nil)
	}

	p.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{Section: "uprobe/gnutls_record_send", EbpfFuncName: "probe_entry_SSL_write", AttachToFuncName: "gnutls_record_send", BinaryPath: path},
			{Section: "uretprobe/gnutls_record_send", EbpfFuncName: "probe_ret_SSL_write", AttachToFuncName: "gnutls_record_send", BinaryPath: path},
			{Section: "uprobe/gnutls_record_recv", EbpfFuncName: "probe_entry_SSL_read", AttachToFuncName: "gnutls_record_recv", BinaryPath: path},
			{Section: "uretprobe/gnutls_record_recv", EbpfFuncName: "probe_ret_SSL_read", AttachToFuncName: "gnutls_record_recv", BinaryPath: path},
		},
		Maps: []*manager.Map{
			{Name: "gnutls_events"},
			{Name: "active_ssl_read_args_map"},
			{Name: "active_ssl_write_args_map"},
			{Name: "data_buffer_heap"},
		},
	}
	p.mapNameToDecoder["gnutls_events"] = &gnutlsEventDecoder{}
	return nil
}

func (p *Probe) setupManagerKeylog() error {
	if p.config.GetEventCollectorAddr() == "" {
		return errors.NewConfigurationError("keylog mode requires an event destination", nil)
	}

	p.bpfManager = p.newMasterSecretManager()
	p.mapNameToDecoder["mastersecret_gnutls_events"] = &masterSecretEventDecoder{}
	return p.registerKeylogSink(p.config.GetEventCollectorAddr(), true)
}

func (p *Probe) setupManagerPcapNG() error {
	if p.config.Ifname == "" {
		return errors.NewConfigurationError("ifname is required for pcap mode", nil)
	}
	if p.config.GetEventCollectorAddr() == "" {
		return errors.NewConfigurationError("pcapng mode requires an event destination", nil)
	}

	p.bpfManager = p.newMasterSecretManager()
	p.bpfManager.Probes = append([]*manager.Probe{
		{Section: "classifier", EbpfFuncName: base.TcFuncNameIngress, Ifname: p.config.Ifname, NetworkDirection: manager.Ingress},
		{Section: "classifier", EbpfFuncName: base.TcFuncNameEgress, Ifname: p.config.Ifname, NetworkDirection: manager.Egress},
		{Section: "kprobe/tcp_sendmsg", EbpfFuncName: "tcp_sendmsg", AttachToFuncName: "tcp_sendmsg"},
		{Section: "kprobe/udp_sendmsg", EbpfFuncName: "udp_sendmsg", AttachToFuncName: "udp_sendmsg"},
	}, p.bpfManager.Probes...)
	p.bpfManager.Maps = append(p.bpfManager.Maps,
		&manager.Map{Name: "skb_events"},
		&manager.Map{Name: "skb_data_buffer_heap"},
		&manager.Map{Name: "network_map"},
	)
	p.mapNameToDecoder["mastersecret_gnutls_events"] = &masterSecretEventDecoder{}
	p.mapNameToDecoder["skb_events"] = &packetEventDecoder{}

	if p.config.KeylogFile != "" {
		if err := p.registerKeylogSink(p.config.KeylogFile, false); err != nil {
			return err
		}
	}

	pcapFileWriter, err := writers.NewWriterFactory().CreateEventSink(writers.EventSinkOptions{
		Address:      p.config.GetEventCollectorAddr(),
		Format:       writers.EventFormatPcapng,
		RotateConfig: writers.NewRotateConfig(p.config.GetEventRotation()),
	})
	if err != nil {
		return fmt.Errorf("failed to create pcap writer: %w", err)
	}
	pcapHandler, err := handlers.NewPcapHandler(
		pcapFileWriter, p.config.Ifname, p.config.PcapFilter, p.Logger())
	if err != nil {
		_ = pcapFileWriter.Close()
		return fmt.Errorf("failed to create pcap handler: %w", err)
	}
	if err := p.Dispatcher().Register(pcapHandler); err != nil {
		_ = pcapHandler.Close()
		return fmt.Errorf("failed to register pcap handler: %w", err)
	}

	pcapKeylogHandler := handlers.NewKeylogHandler(
		writers.NewPcapKeylogWriter(pcapHandler.PcapWriter()))
	if err := p.Dispatcher().Register(pcapKeylogHandler); err != nil {
		_ = pcapHandler.Close()
		return fmt.Errorf("failed to register pcap keylog handler: %w", err)
	}
	p.Logger().Info().Str("pcap_sink", pcapFileWriter.Name()).Msg("Pcap handler registered")
	return nil
}

func (p *Probe) newMasterSecretManager() *manager.Manager {
	path := p.config.GnutlsPath
	return &manager.Manager{
		Probes: []*manager.Probe{
			{Section: "uprobe/gnutls_handshake", EbpfFuncName: "uprobe_gnutls_master_key", AttachToFuncName: "gnutls_handshake", BinaryPath: path},
			{Section: "uretprobe/gnutls_handshake", EbpfFuncName: "uretprobe_gnutls_master_key", AttachToFuncName: "gnutls_handshake", BinaryPath: path},
		},
		Maps: []*manager.Map{
			{Name: "mastersecret_gnutls_events"},
			{Name: "gnutls_session_maps"},
			{Name: "bpf_context"},
			{Name: "bpf_context_gen"},
		},
	}
}

func (p *Probe) registerKeylogSink(address string, primary bool) error {
	options := writers.EventSinkOptions{
		Address: address,
		Format:  writers.EventFormatKeylog,
	}
	if primary {
		options.RotateConfig = writers.NewRotateConfig(p.config.GetEventRotation())
	}
	fileWriter, err := writers.NewWriterFactory().CreateEventSink(options)
	if err != nil {
		return fmt.Errorf("failed to create keylog writer: %w", err)
	}

	keylogWriter := writers.NewKeylogWriter(fileWriter)
	keylogHandler := handlers.NewKeylogHandler(keylogWriter)
	if err := p.Dispatcher().Register(keylogHandler); err != nil {
		_ = keylogWriter.Close()
		return fmt.Errorf("failed to register keylog handler: %w", err)
	}
	p.Logger().Info().Str("keylog_sink", fileWriter.Name()).Msg("Keylog handler registered")
	return nil
}

func (p *Probe) getManagerOptions() manager.Options {
	opts := manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{LogSizeStart: 2097152},
		},
		RLimit: &unix.Rlimit{Cur: math.MaxUint64, Max: math.MaxUint64},
	}
	if !p.config.EnableGlobalVar() {
		if p.config.GetPid() != 0 || p.config.GetUid() != 0 || p.config.GetCGroupPath() != "" {
			p.Logger().Warn().Msg("PID, UID, and cgroup filters are unavailable on kernels without global variable rewriting")
		}
		return opts
	}

	kernelVersion, _ := kernel.HostVersion()
	kernelLess52 := uint64(0)
	if kernelVersion < kernel.VersionCode(5, 2, 0) {
		kernelLess52 = 1
	}
	var cgroupID uint64
	if p.config.GetCGroupPath() != "" {
		var err error
		cgroupID, err = pkgebpf.GetCgroupIdFromPath(p.config.GetCGroupPath())
		if err != nil {
			p.Logger().Warn().Err(err).Str("cgroup_path", p.config.GetCGroupPath()).
				Msg("Failed to resolve cgroup id; cgroup filtering disabled")
			cgroupID = 0
		}
	}
	opts.ConstantEditors = []manager.ConstantEditor{
		{Name: "target_pid", Value: p.config.GetPid()},
		{Name: "target_uid", Value: p.config.GetUid()},
		{Name: "less52", Value: kernelLess52},
		{Name: "target_cgroup_id", Value: cgroupID},
	}
	return opts
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	decoder, found := p.eventFuncMaps[em]
	return decoder, found
}

type gnutlsEventDecoder struct{}

func (d *gnutlsEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *gnutlsEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &Event{}, true
}

type masterSecretEventDecoder struct{}

func (d *masterSecretEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &MasterSecretEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *masterSecretEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &MasterSecretEvent{}, true
}

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
