// Copyright © 2022 Hengqi Chen
package module

import (
	"bytes"
	"context"
	"ecapture/assets"
	"ecapture/pkg/proc"
	"ecapture/user/config"
	"ecapture/user/event"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

func init() {
	mod := &GoTLSProbe{}
	Register(mod)
}

const (
	goTlsWriteFunc        = "crypto/tls.(*Conn).writeRecordLocked"
	goTlsMasterSecretFunc = "crypto/tls.(*Config).writeKeyLog"
)

var (
	NotGoCompiledBin = errors.New("It is not a program compiled in the Go language.")
)

// GoTLSProbe represents a probe for Go SSL
type GoTLSProbe struct {
	Module
	MTCProbe
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	keyloggerFilename string
	keylogger         *os.File
	masterSecrets     map[string]bool
	eBPFProgramType   EBPFPROGRAMTYPE
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

	g.keyloggerFilename = MasterSecretKeyLogName
	file, err := os.OpenFile(g.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	g.keylogger = file

	var writeFile = g.conf.(*config.GoTLSConfig).Write
	if len(writeFile) > 0 {
		g.eBPFProgramType = EbpfprogramtypeOpensslTc
		fileInfo, err := filepath.Abs(writeFile)
		if err != nil {
			return err
		}
		g.pcapngFilename = fileInfo
	} else {
		g.eBPFProgramType = EbpfprogramtypeOpensslUprobe
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
	case EbpfprogramtypeOpensslTc:
		g.logger.Printf("%s\tTC MODEL\n", g.Name())
		err = g.setupManagersTC()
	case EbpfprogramtypeOpensslUprobe:
		g.logger.Printf("%s\tUPROBE MODEL\n", g.Name())
		err = g.setupManagersUprobe()
	default:
		g.logger.Printf("%s\tUPROBE MODEL\n", g.Name())
		err = g.setupManagersUprobe()
	}
	if err != nil {
		return err
	}

	var bpfFileName = g.geteBPFName("user/bytecode/gotls_kern.o")
	g.logger.Printf("%s\tBPF bytecode filename:%s\n", g.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return err
	}

	if err = g.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), g.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}
	// start the bootstrap manager
	if err = g.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}

	// 加载map信息，map对应events decode表。
	switch g.eBPFProgramType {
	case EbpfprogramtypeOpensslTc:
		err = g.initDecodeFunTC()
	case EbpfprogramtypeOpensslUprobe:
		err = g.initDecodeFun()
	default:
		err = g.initDecodeFun()
	}
	if err != nil {
		return err
	}
	return nil
}

func (g *GoTLSProbe) setupManagersUprobe() error {
	var (
		sec, msSec, readSec string
		fn, msFn, readFn    string
	)

	if g.isRegisterABI {
		sec = "uprobe/gotls_write_register"
		fn = "gotls_write_register"
		readSec = "uprobe/gotls_read_register"
		readFn = "gotls_read_register"
		msSec = "uprobe/gotls_mastersecret_register"
		msFn = "gotls_mastersecret_register"
	} else {
		sec = "uprobe/gotls_write_stack"
		fn = "gotls_write_stack"
		readSec = "uprobe/gotls_read_stack"
		readFn = "gotls_read_stack"
		msSec = "uprobe/gotls_mastersecret_stack"
		msFn = "gotls_mastersecret_stack"
	}
	g.logger.Printf("%s\teBPF Function Name:%s, isRegisterABI:%t\n", g.Name(), fn, g.isRegisterABI)
	g.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: goTlsWriteFunc,
				BinaryPath:       g.path,
			},
			{
				Section:          msSec,
				EbpfFuncName:     msFn,
				AttachToFuncName: goTlsMasterSecretFunc,
				BinaryPath:       g.path,
				UID:              "uprobe_gotls_master_secret",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "mastersecret_go_events",
			},
			{
				Name: "events",
			},
		},
	}

	readOffsets := g.conf.(*config.GoTLSConfig).ReadTlsAddrs
	//g.bpfManager.Probes = []*manager.Probe{}
	for _, v := range readOffsets {
		var uid = fmt.Sprintf("%s_%d", readFn, v)
		g.logger.Printf("%s\tadd uretprobe function :%s, offset:0x%X\n", g.Name(), config.GoTlsReadFunc, v)
		g.bpfManager.Probes = append(g.bpfManager.Probes, &manager.Probe{
			Section:          readSec,
			EbpfFuncName:     readFn,
			AttachToFuncName: config.GoTlsReadFunc,
			BinaryPath:       g.path,
			UprobeOffset:     uint64(v),
			UID:              uid,
		})
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

// 通过elf的常量替换方式传递数据
func (g *GoTLSProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(g.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(g.conf.GetUid()),
		},
		{
			Name:  "target_port",
			Value: uint64(g.conf.(*config.GoTLSConfig).Port),
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

func (g *GoTLSProbe) initDecodeFun() error {

	m, found, err := g.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tls_events")
	}

	g.eventMaps = append(g.eventMaps, m)
	gotlsEvent := &event.GoTLSEvent{}
	//sslEvent.SetModule(g)
	g.eventFuncMaps[m] = gotlsEvent
	// master secrets map at ebpf code
	MasterkeyEventsMap, found, err := g.bpfManager.GetMap("mastersecret_go_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	g.eventMaps = append(g.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	// goTLS Event struct
	masterkeyEvent = &event.MasterSecretGotlsEvent{}

	g.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}

func (g *GoTLSProbe) DecodeFun(m *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := g.eventFuncMaps[m]
	return fun, found
}

func (g *GoTLSProbe) Close() error {

	if g.eBPFProgramType == EbpfprogramtypeOpensslTc {
		g.logger.Printf("%s\tsaving pcapng file %s\n", g.Name(), g.pcapngFilename)
		i, err := g.savePcapng()
		if err != nil {
			g.logger.Printf("%s\tsave pcanNP failed, error:%v. \n", g.Name(), err)
		}
		if i == 0 {
			g.logger.Printf("nothing captured, please check your network interface, see \"ecapture tls -h\" for more information.")
		} else {
			g.logger.Printf("%s\t save %d packets into pcapng file.\n", g.Name(), i)
		}
	}

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

	var k = fmt.Sprintf("%s-%02x", label, clientRandom)

	_, f := g.masterSecrets[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}

	// TODO 保存多个lable 整组里？？？
	// save to file
	var b string
	b = fmt.Sprintf("%s %02x %02x\n", label, clientRandom, secret)
	l, e := g.keylogger.WriteString(b)
	if e != nil {
		g.logger.Fatalf("%s: save masterSecrets to file error:%s", secretEvent.String(), e.Error())
		return
	}
	g.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", label, clientRandom, l)
	e = g.savePcapngSslKeyLog([]byte(b))
	if e != nil {
		g.logger.Fatalf("%s: save masterSecrets to pcapng error:%s", secretEvent.String(), e.Error())
		return
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
	//g.logger.Println(eventStruct)
}
