// Copyright © 2022 Hengqi Chen
package module

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ecapture/assets"
	"ecapture/pkg/proc"
	"ecapture/user/config"
	"ecapture/user/event"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

func init() {
	mod := &GoTLSProbe{}
	mod.name = ModuleNameGotls
	mod.mType = ProbeTypeUprobe
	Register(mod)
}

var NotGoCompiledBin = errors.New("It is not a program compiled in the Go language.")

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

func (g *GoTLSProbe) Init(ctx context.Context, l *log.Logger, cfg config.IConfig) error {
	g.Module.Init(ctx, l, cfg)
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
		g.logger.Printf("%s\tmaster key keylogger: %s\n", g.Name(), g.keyloggerFilename)
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
		g.logger.Printf("%s\tKeylog MODEL\n", g.Name())
		err = g.setupManagersKeylog()
	case TlsCaptureModelTypePcap:
		g.logger.Printf("%s\tPcap MODEL\n", g.Name())
		err = g.setupManagersPcap()
	case TlsCaptureModelTypeText:
		g.logger.Printf("%s\tText MODEL\n", g.Name())
		err = g.setupManagersText()
	default:
		g.logger.Printf("%s\tText MODEL\n", g.Name())
		err = g.setupManagersText()
	}
	if err != nil {
		return err
	}

	if pcapFilter := g.conf.(*config.GoTLSConfig).PcapFilter; pcapFilter != "" {
		ebpfFuncs := []string{tcFuncNameIngress, tcFuncNameEgress}
		g.bpfManager.InstructionPatchers = prepareInsnPatchers(g.bpfManager,
			ebpfFuncs, pcapFilter)
	}

	bpfFileName := g.geteBPFName("user/bytecode/gotls_kern.o")
	g.logger.Printf("%s\tBPF bytecode filename:%s\n", g.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return err
	}

	if err = g.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), g.bpfManagerOptions); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			g.logger.Printf("%s\tcouldn't verify bpf prog: %+v", g.Name(), ve)
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
		g.logger.Printf("%s\ttarget all process. \n", g.Name())
	} else {
		g.logger.Printf("%s\ttarget PID:%d \n", g.Name(), g.conf.GetPid())
	}

	if g.conf.GetUid() <= 0 {
		g.logger.Printf("%s\ttarget all users. \n", g.Name())
	} else {
		g.logger.Printf("%s\ttarget UID:%d \n", g.Name(), g.conf.GetUid())
	}

	return editor
}

func (g *GoTLSProbe) DecodeFun(m *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := g.eventFuncMaps[m]
	return fun, found
}

func (g *GoTLSProbe) Close() error {
	g.logger.Printf("%s\tclose. \n", g.Name())
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

	// TODO 保存多个lable 整组里？？？
	// save to file
	var b string
	var e error
	b = fmt.Sprintf("%s %02x %02x\n", label, clientRandom, secret)
	switch g.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		var l int
		l, e = g.keylogger.WriteString(b)
		if e != nil {
			g.logger.Fatalf("%s: save masterSecrets to file error:%s", secretEvent.String(), e.Error())
			return
		}
		g.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", label, clientRandom, l)
	case TlsCaptureModelTypePcap:
		e = g.savePcapngSslKeyLog([]byte(b))
		if e != nil {
			g.logger.Fatalf("%s: save masterSecrets to pcapng error:%s", secretEvent.String(), e.Error())
			return
		}
	default:
		g.logger.Fatalf("unhandled default case with eBPF Program type:%d", g.eBPFProgramType)
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
			g.logger.Printf("%s\t save packet error %s .\n", g.Name(), err.Error())
		}
	}
}

func (g *GoTLSProbe) Events() []*ebpf.Map {
	return g.eventMaps
}
