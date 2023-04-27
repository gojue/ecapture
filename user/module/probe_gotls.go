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

func (this *GoTLSProbe) Init(ctx context.Context, l *log.Logger, cfg config.IConfig) error {
	this.Module.Init(ctx, l, cfg)
	this.conf = cfg
	this.Module.SetChild(this)

	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)

	this.masterSecrets = make(map[string]bool)
	this.path = cfg.(*config.GoTLSConfig).Path
	ver, err := proc.ExtraceGoVersion(this.path)
	if err != nil {
		return fmt.Errorf("%s, error:%v", NotGoCompiledBin, err)
	}

	// supported at 1.17 via https://github.com/golang/go/issues/40724
	if ver.After(1, 17) {
		this.isRegisterABI = true
	}

	this.keyloggerFilename = MasterSecretKeyLogName
	file, err := os.OpenFile(this.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	this.keylogger = file

	var writeFile = this.conf.(*config.GoTLSConfig).Write
	if len(writeFile) > 0 {
		this.eBPFProgramType = EbpfprogramtypeOpensslTc
		fileInfo, err := filepath.Abs(writeFile)
		if err != nil {
			return err
		}
		this.pcapngFilename = fileInfo
	} else {
		this.eBPFProgramType = EbpfprogramtypeOpensslUprobe
		this.logger.Printf("%s\tmaster key keylogger: %s\n", this.Name(), this.keyloggerFilename)
	}

	var ts unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return err
	}
	startTime := ts.Nano()
	bootTime := time.Now().UnixNano() - startTime

	this.startTime = uint64(startTime)
	this.bootTime = uint64(bootTime)

	this.tcPackets = make([]*TcPacket, 0, 1024)
	this.tcPacketLocker = &sync.Mutex{}
	this.masterKeyBuffer = bytes.NewBuffer([]byte{})
	return nil
}

func (this *GoTLSProbe) Name() string {
	return ModuleNameGotls
}

func (this *GoTLSProbe) Start() error {
	return this.start()
}

func (this *GoTLSProbe) start() error {
	var err error
	switch this.eBPFProgramType {
	case EbpfprogramtypeOpensslTc:
		this.logger.Printf("%s\tTC MODEL\n", this.Name())
		err = this.setupManagersTC()
	case EbpfprogramtypeOpensslUprobe:
		this.logger.Printf("%s\tUPROBE MODEL\n", this.Name())
		err = this.setupManagersUprobe()
	default:
		this.logger.Printf("%s\tUPROBE MODEL\n", this.Name())
		err = this.setupManagersUprobe()
	}
	if err != nil {
		return err
	}

	var bpfFileName = this.geteBPFName("user/bytecode/gotls_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename:%s\n", this.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return err
	}

	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}
	// start the bootstrap manager
	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}

	// 加载map信息，map对应events decode表。
	switch this.eBPFProgramType {
	case EbpfprogramtypeOpensslTc:
		err = this.initDecodeFunTC()
	case EbpfprogramtypeOpensslUprobe:
		err = this.initDecodeFun()
	default:
		err = this.initDecodeFun()
	}
	if err != nil {
		return err
	}
	return nil
}

func (this *GoTLSProbe) setupManagersUprobe() error {
	var (
		sec, msSec, readSec string
		fn, msFn, readFn    string
	)

	if this.isRegisterABI {
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
	this.logger.Printf("%s\teBPF Function Name:%s, isRegisterABI:%t\n", this.Name(), fn, this.isRegisterABI)
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: goTlsWriteFunc,
				BinaryPath:       this.path,
			},
			// gotls master secrets
			// crypto/tls.(*Config).writeKeyLog
			// crypto/tls/common.go
			/*
				func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
				}
			*/
			{
				Section:          msSec,
				EbpfFuncName:     msFn,
				AttachToFuncName: goTlsMasterSecretFunc,
				BinaryPath:       this.path,
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

	readOffsets := this.conf.(*config.GoTLSConfig).ReadTlsAddrs
	for _, v := range readOffsets {
		this.logger.Printf("%s\tadd uretprobe function :%s, offset:%x\n", this.Name(), config.GoTlsReadFunc, v)
		this.bpfManager.Probes = append(this.bpfManager.Probes, &manager.Probe{
			Section:      readSec,
			EbpfFuncName: readFn,
			//AttachToFuncName: config.GoTlsReadFunc,
			AttachToFuncName: "crypto/tls.(*Conn).Write",
			BinaryPath:       this.path,
			//UprobeOffset:     uint64(v),
			UID: fmt.Sprintf("%s_%x", readFn, v),
		})
		break
	}
	this.bpfManagerOptions = manager.Options{
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

	if this.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		this.bpfManagerOptions.ConstantEditors = this.constantEditor()
	}
	return nil
}

// 通过elf的常量替换方式传递数据
func (this *GoTLSProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(this.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(this.conf.GetUid()),
		},
		{
			Name:  "target_port",
			Value: uint64(this.conf.(*config.GoTLSConfig).Port),
		},
	}

	if this.conf.GetPid() <= 0 {
		this.logger.Printf("%s\ttarget all process. \n", this.Name())
	} else {
		this.logger.Printf("%s\ttarget PID:%d \n", this.Name(), this.conf.GetPid())
	}

	if this.conf.GetUid() <= 0 {
		this.logger.Printf("%s\ttarget all users. \n", this.Name())
	} else {
		this.logger.Printf("%s\ttarget UID:%d \n", this.Name(), this.conf.GetUid())
	}

	return editor
}

func (this *GoTLSProbe) initDecodeFun() error {

	m, found, err := this.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tls_events")
	}

	this.eventMaps = append(this.eventMaps, m)
	gotlsEvent := &event.GoTLSEvent{}
	//sslEvent.SetModule(this)
	this.eventFuncMaps[m] = gotlsEvent
	// master secrets map at ebpf code
	MasterkeyEventsMap, found, err := this.bpfManager.GetMap("mastersecret_go_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	this.eventMaps = append(this.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	// goTLS Event struct
	masterkeyEvent = &event.MasterSecretGotlsEvent{}

	this.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}

func (this *GoTLSProbe) DecodeFun(m *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[m]
	return fun, found
}

func (this *GoTLSProbe) Close() error {

	if this.eBPFProgramType == EbpfprogramtypeOpensslTc {
		this.logger.Printf("%s\tsaving pcapng file %s\n", this.Name(), this.pcapngFilename)
		i, err := this.savePcapng()
		if err != nil {
			this.logger.Printf("%s\tsave pcanNP failed, error:%v. \n", this.Name(), err)
		}
		if i == 0 {
			this.logger.Printf("nothing captured, please check your network interface, see \"ecapture tls -h\" for more information.")
		} else {
			this.logger.Printf("%s\t save %d packets into pcapng file.\n", this.Name(), i)
		}
	}

	this.logger.Printf("%s\tclose. \n", this.Name())
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	return this.Module.Close()
}

func (this *GoTLSProbe) saveMasterSecret(secretEvent *event.MasterSecretGotlsEvent) {
	var label, clientRandom, secret string
	label = string(secretEvent.Label[0:secretEvent.LabelLen])
	clientRandom = string(secretEvent.ClientRandom[0:secretEvent.ClientRandomLen])
	secret = string(secretEvent.MasterSecret[0:secretEvent.MasterSecretLen])

	var k = fmt.Sprintf("%s-%02x", label, clientRandom)

	_, f := this.masterSecrets[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}

	// TODO 保存多个lable 整组里？？？
	// save to file
	var b string
	b = fmt.Sprintf("%s %02x %02x\n", label, clientRandom, secret)
	l, e := this.keylogger.WriteString(b)
	if e != nil {
		this.logger.Fatalf("%s: save masterSecrets to file error:%s", secretEvent.String(), e.Error())
		return
	}
	this.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", label, clientRandom, l)
	e = this.savePcapngSslKeyLog([]byte(b))
	if e != nil {
		this.logger.Fatalf("%s: save masterSecrets to pcapng error:%s", secretEvent.String(), e.Error())
		return
	}

}

func (this *GoTLSProbe) Dispatcher(eventStruct event.IEventStruct) {
	// detect eventStruct type
	switch eventStruct.(type) {
	case *event.MasterSecretGotlsEvent:
		this.saveMasterSecret(eventStruct.(*event.MasterSecretGotlsEvent))
	case *event.TcSkbEvent:
		err := this.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
		if err != nil {
			this.logger.Printf("%s\t save packet error %s .\n", this.Name(), err.Error())
		}
	}
	//this.logger.Println(eventStruct)
}
