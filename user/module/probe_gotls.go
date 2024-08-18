// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// Copyright © 2022 Hengqi Chen
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
	"github.com/rs/zerolog"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/pkg/proc"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

var NotGoCompiledBin = errors.New("it is not a program compiled in the Go language")

// GoTLSProbe represents a probe for Go SSL
type GoTLSProbe struct {
	MTCProbe
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	keyloggerFilename string
	keylogger         *os.File
	masterSecrets     map[string]bool
	eBPFProgramType   TlsCaptureModelType
	path              string
	isRegisterABI     bool
}

func (g *GoTLSProbe) Init(ctx context.Context, l *zerolog.Logger, cfg config.IConfig, ecw io.Writer) error {
	e := g.Module.Init(ctx, l, cfg, ecw)
	if e != nil {
		return e
	}
	g.conf = cfg
	g.Module.SetChild(g)

	g.eventMaps = make([]*ebpf.Map, 0, 2)
	g.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)

	g.masterSecrets = make(map[string]bool)
	g.path = cfg.(*config.GoTLSConfig).Path
	ver, err := proc.ExtraceGoVersion(g.path)
	if err != nil {
		return fmt.Errorf("%s, error:%v", NotGoCompiledBin, err)
	}

	// supported at 1.17 via https://github.com/golang/go/issues/40724
	if ver.After(1, 17) {
		g.isRegisterABI = true
	}

	model := g.conf.(*config.GoTLSConfig).Model
	switch model {
	case config.TlsCaptureModelKey, config.TlsCaptureModelKeylog:
		g.eBPFProgramType = TlsCaptureModelTypeKeylog
		g.keyloggerFilename = g.conf.(*config.GoTLSConfig).KeylogFile
		file, err := os.OpenFile(g.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		g.keylogger = file
	case config.TlsCaptureModelPcap, config.TlsCaptureModelPcapng:
		pcapFile := g.conf.(*config.GoTLSConfig).PcapFile
		g.eBPFProgramType = TlsCaptureModelTypePcap
		fileInfo, err := filepath.Abs(pcapFile)
		if err != nil {
			return err
		}
		g.pcapngFilename = fileInfo
	case config.TlsCaptureModelText:
		fallthrough
	default:
		g.eBPFProgramType = TlsCaptureModelTypeText
	}
	g.logger.Info().Str("model", g.eBPFProgramType.String()).Str("keylogFile", g.keyloggerFilename).Msg("GoTlsProbe init")

	var ts unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return err
	}
	startTime := ts.Nano()
	bootTime := time.Now().UnixNano() - startTime

	g.startTime = uint64(startTime)
	g.bootTime = uint64(bootTime)

	g.tcPackets = make([]*TcPacket, 0, 1024)
	g.tcPacketsChan = make(chan *TcPacket, 2048)
	g.tcPacketLocker = &sync.Mutex{}
	g.masterKeyBuffer = bytes.NewBuffer([]byte{})
	return nil
}

func (g *GoTLSProbe) Name() string {
	return ModuleNameGotls
}

func (g *GoTLSProbe) Start() error {
	return g.start()
}

func (g *GoTLSProbe) start() error {
	var err error
	switch g.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		err = g.setupManagersKeylog()
	case TlsCaptureModelTypePcap:
		err = g.setupManagersPcap()
	case TlsCaptureModelTypeText:
		err = g.setupManagersText()
	default:
		err = g.setupManagersText()
	}
	if err != nil {
		return err
	}

	pcapFilter := g.conf.(*config.GoTLSConfig).PcapFilter
	if g.eBPFProgramType == TlsCaptureModelTypePcap && pcapFilter != "" {
		ebpfFuncs := []string{tcFuncNameIngress, tcFuncNameEgress}
		g.bpfManager.InstructionPatchers = prepareInsnPatchers(g.bpfManager,
			ebpfFuncs, pcapFilter)
	}

	bpfFileName := g.geteBPFName("user/bytecode/gotls_kern.o")
	g.logger.Info().Str("bpfFileName", bpfFileName).Msg("BPF bytecode file is matched.")
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		g.logger.Error().Err(err).Strs("bytecode files", assets.AssetNames()).Msg("couldn't find bpf bytecode file")
		return err
	}

	if err = g.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), g.bpfManagerOptions); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			g.logger.Warn().Err(ve).Msg("couldn't verify bpf prog")
		}
		return fmt.Errorf("couldn't init manager %v", err)
	}
	// start the bootstrap manager
	if err = g.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}

	// 加载map信息，map对应events decode表。
	switch g.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		err = g.initDecodeFunKeylog()
	case TlsCaptureModelTypePcap:
		err = g.initDecodeFunPcap()
	case TlsCaptureModelTypeText:
		err = g.initDecodeFunText()
	default:
		err = g.initDecodeFunText()
	}
	if err != nil {
		return err
	}
	return nil
}

// 通过elf的常量替换方式传递数据
func (g *GoTLSProbe) constantEditor() []manager.ConstantEditor {
	editor := []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(g.conf.GetPid()),
			// FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(g.conf.GetUid()),
		},
	}

	if g.conf.GetPid() <= 0 {
		g.logger.Info().Msg("target all process.")

	} else {
		g.logger.Info().Uint64("target PID", g.conf.GetPid()).Msg("target process.")

	}

	if g.conf.GetUid() <= 0 {
		g.logger.Info().Msg("target all users.")
	} else {
		g.logger.Info().Uint64("target UID", g.conf.GetUid()).Msg("target user.")
	}

	return editor
}

func (g *GoTLSProbe) DecodeFun(m *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := g.eventFuncMaps[m]
	return fun, found
}

func (g *GoTLSProbe) Close() error {
	g.logger.Info().Msg("module close.")
	if err := g.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	return g.Module.Close()
}

func (g *GoTLSProbe) saveMasterSecret(secretEvent *event.MasterSecretGotlsEvent) {
	var label, clientRandom, secret string
	label = string(secretEvent.Label[0:secretEvent.LabelLen])
	clientRandom = string(secretEvent.ClientRandom[0:secretEvent.ClientRandomLen])
	secret = string(secretEvent.MasterSecret[0:secretEvent.MasterSecretLen])

	k := fmt.Sprintf("%s-%02x", label, clientRandom)

	_, f := g.masterSecrets[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}

	// 保存到多个lable 整组里
	// save to file
	var b, cr string
	var e error
	cr = fmt.Sprintf("%02x", clientRandom)
	b = fmt.Sprintf("%s %s %02x\n", label, cr, secret)

	switch g.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		var l int
		l, e = g.keylogger.WriteString(b)
		if e != nil {
			g.logger.Warn().Err(e).Str("clientRandom", cr).Msg("save masterSecrets to keylog error")
			return
		}
		g.logger.Info().Str("clientRandom", cr).Str("label", label).Int("bytes", l).Msg("save CLIENT_RANDOM success")
	case TlsCaptureModelTypePcap:
		e = g.savePcapngSslKeyLog([]byte(b))
		if e != nil {
			g.logger.Warn().Err(e).Str("clientRandom", cr).Msg("save masterSecrets to pcapNG error")
			return
		}
	default:
		g.logger.Warn().Str("clientRandom", cr).Uint8("eBPFProgramType", uint8(g.eBPFProgramType)).Msg("unhandled default case with eBPF Program type")
	}
}

func (g *GoTLSProbe) Dispatcher(eventStruct event.IEventStruct) {
	// detect eventStruct type
	switch eventStruct.(type) {
	case *event.MasterSecretGotlsEvent:
		g.saveMasterSecret(eventStruct.(*event.MasterSecretGotlsEvent))
	case *event.TcSkbEvent:
		err := g.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
		if err != nil {
			g.logger.Warn().Err(err).Msg("save packet error.")
		}
	}
}

func (g *GoTLSProbe) Events() []*ebpf.Map {
	return g.eventMaps
}

func init() {
	RegisteFunc(NewGoTLSProbe)
}

func NewGoTLSProbe() IModule {
	mod := &GoTLSProbe{}
	mod.name = ModuleNameGotls
	mod.mType = ProbeTypeUprobe
	return mod
}
