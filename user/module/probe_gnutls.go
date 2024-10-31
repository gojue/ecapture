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

package module

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
)

type MGnutlsProbe struct {
	MTCProbe
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	pidConns  map[uint32]map[uint32]string
	pidLocker sync.Locker

	keyloggerFilename string
	keylogger         *os.File
	masterKeys        map[string]bool
	eBPFProgramType   TlsCaptureModelType
}

// 对象初始化
func (g *MGnutlsProbe) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, ecw io.Writer) error {
	err := g.Module.Init(ctx, logger, conf, ecw)
	if err != nil {
		return err
	}
	g.conf = conf
	g.Module.SetChild(g)
	g.eventMaps = make([]*ebpf.Map, 0, 2)
	g.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	g.pidConns = make(map[uint32]map[uint32]string)
	g.pidLocker = new(sync.Mutex)
	g.masterKeys = make(map[string]bool)
	model := g.conf.(*config.GnutlsConfig).Model
	switch model {
	case config.TlsCaptureModelKey, config.TlsCaptureModelKeylog:
		g.eBPFProgramType = TlsCaptureModelTypeKeylog
		g.keyloggerFilename = g.conf.(*config.GnutlsConfig).KeylogFile
		file, err := os.OpenFile(g.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		g.keylogger = file
	case config.TlsCaptureModelPcap, config.TlsCaptureModelPcapng:
		g.eBPFProgramType = TlsCaptureModelTypePcap
		pcapFile := g.conf.(*config.GnutlsConfig).PcapFile
		fileInfo, err := filepath.Abs(pcapFile)
		if err != nil {
			g.logger.Warn().Err(err).Str("pcapFile", pcapFile).Str("eBPFProgramType", g.eBPFProgramType.String()).Msg("pcapFile not found")
			return err
		}
		g.tcPacketsChan = make(chan *TcPacket, 2048)
		g.tcPackets = make([]*TcPacket, 0, 256)
		g.pcapngFilename = fileInfo
	case config.TlsCaptureModelText:
		fallthrough
	default:
		g.eBPFProgramType = TlsCaptureModelTypeText
	}

	var ts unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return err
	}
	startTime := ts.Nano()
	bootTime := time.Now().UnixNano() - startTime

	g.startTime = uint64(startTime)
	g.bootTime = uint64(bootTime)

	g.tcPacketLocker = &sync.Mutex{}
	g.masterKeyBuffer = bytes.NewBuffer([]byte{})

	g.logger.Info().Str("model", g.eBPFProgramType.String()).Str("eBPFProgramType", g.eBPFProgramType.String()).Msg("GnuTlsProbe init")
	return nil
}

func (g *MGnutlsProbe) Start() error {
	if err := g.start(); err != nil {
		return err
	}
	return nil
}

func (g *MGnutlsProbe) start() error {
	// fetch ebpf assets
	var err error
	bpfFileName := g.geteBPFName("user/bytecode/gnutls_kern.o")
	g.logger.Info().Str("bytecode filename", bpfFileName).Msg("BPF bytecode loaded")
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		g.logger.Error().Err(err).Strs("bytecode files", assets.AssetNames()).Msg("couldn't find bpf bytecode file")
		return fmt.Errorf("couldn't find asset %v", err)
	}

	// setup the managers
	switch g.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		err = g.setupManagersKeylog()
	case TlsCaptureModelTypePcap:
		err = g.setupManagersPcap()
		pcapFilter := g.conf.(*config.GnutlsConfig).PcapFilter
		if g.eBPFProgramType == TlsCaptureModelTypePcap && pcapFilter != "" {
			ebpfFuncs := []string{tcFuncNameIngress, tcFuncNameEgress}
			g.bpfManager.InstructionPatchers = prepareInsnPatchers(g.bpfManager,
				ebpfFuncs, pcapFilter)
		}
	case TlsCaptureModelTypeText:
		fallthrough
	default:
		err = g.setupManagers()
	}
	if err != nil {
		return fmt.Errorf("tls(gnutls) module couldn't find binPath %v", err)
	}

	// initialize the bootstrap manager
	if err = g.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), g.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = g.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	// 加载map信息，map对应events decode表。
	switch g.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		err = g.initDecodeFunKeylog()
	case TlsCaptureModelTypePcap:
		err = g.initDecodeFunPcap()
	case TlsCaptureModelTypeText:
		fallthrough
	default:
		err = g.initDecodeFunText()
	}
	if err != nil {
		return err
	}

	return nil
}

func (g *MGnutlsProbe) Close() error {
	if err := g.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return g.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (g *MGnutlsProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(g.conf.GetPid()),
			//FailOnMissing: true,
		},
	}

	if g.conf.GetPid() <= 0 {
		g.logger.Info().Msg("target all process.")
	} else {
		g.logger.Info().Uint64("target pid", g.conf.GetPid()).Msg("target process.")
	}
	return editor
}

func (g *MGnutlsProbe) setupManagers() error {
	var binaryPath string
	switch g.conf.(*config.GnutlsConfig).ElfType {
	case config.ElfTypeSo:
		binaryPath = g.conf.(*config.GnutlsConfig).Gnutls
	default:
		//如果没找到  "/lib/x86_64-linux-gnu/libgnutls.so.30"
		binaryPath = path.Join(defaultSoPath, "libgnutls.so.30")
	}
	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	g.logger.Info().Str("binaryPath", binaryPath).Uint8("elfType", g.conf.(*config.GnutlsConfig).ElfType).Msg("gnutls binary path")
	g.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/gnutls_record_send",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "gnutls_record_send",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/gnutls_record_send",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "gnutls_record_send",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uprobe/gnutls_record_recv",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "gnutls_record_recv",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/gnutls_record_recv",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "gnutls_record_recv",
				BinaryPath:       binaryPath,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "gnutls_events",
			},
		},
	}

	g.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if g.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		g.bpfManagerOptions.ConstantEditors = g.constantEditor()
	}
	return nil
}

func (g *MGnutlsProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := g.eventFuncMaps[em]
	return fun, found
}

func (g *MGnutlsProbe) initDecodeFunText() error {
	//GnutlsEventsMap 与解码函数映射
	GnutlsEventsMap, found, err := g.bpfManager.GetMap("gnutls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:gnutls_events")
	}
	g.eventMaps = append(g.eventMaps, GnutlsEventsMap)
	g.eventFuncMaps[GnutlsEventsMap] = &event.GnutlsDataEvent{}

	return nil
}

func (g *MGnutlsProbe) Events() []*ebpf.Map {
	return g.eventMaps
}

func (g *MGnutlsProbe) Dispatcher(eventStruct event.IEventStruct) {
	// detect eventStruct type
	switch eventStruct.(type) {
	case *event.MasterSecretGnutlsEvent:
		g.saveMasterSecret(eventStruct.(*event.MasterSecretGnutlsEvent))
	case *event.TcSkbEvent:
		err := g.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
		if err != nil {
			g.logger.Warn().Err(err).Msg("save packet error.")
		}
	}
}

func init() {
	RegisteFunc(NewGnutlsProbe)
}

func NewGnutlsProbe() IModule {
	mod := &MGnutlsProbe{}
	mod.name = ModuleNameGnutls
	mod.mType = ProbeTypeUprobe
	return mod
}
