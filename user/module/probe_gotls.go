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
	goTlsHookFunc         = "crypto/tls.(*Conn).writeRecordLocked"
	goTlsMasterSecretFunc = "crypto/tls.(*Config).writeKeyLog"
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
		return err
	}

	// supported at 1.17 via https://github.com/golang/go/issues/40724
	if ver.After(1, 17) {
		this.isRegisterABI = true
	}

	this.keyloggerFilename = "ecapture_masterkey.log"
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
		sec, ms_sec string
		fn, ms_fn   string
	)

	if this.isRegisterABI {
		sec = "uprobe/gotls_text_register"
		fn = "gotls_text_register"
		ms_sec = "uprobe/gotls_masterkey_register"
		ms_fn = "gotls_masterkey_register"
	} else {
		sec = "uprobe/gotls_text_stack"
		fn = "gotls_text_stack"
		ms_sec = "uprobe/gotls_masterkey_stack"
		ms_fn = "gotls_masterkey_stack"
	}
	this.logger.Printf("%s\teBPF Function Name:%s, isRegisterABI:%t\n", this.Name(), fn, this.isRegisterABI)
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: goTlsHookFunc,
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
				Section:          ms_sec,
				EbpfFuncName:     ms_fn,
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
	return this.Module.Close()
}

func (this *GoTLSProbe) saveMasterSecret(secretEvent *event.MasterSecretGotlsEvent) {
	var k = fmt.Sprintf("%s-%02x", secretEvent.Lable, secretEvent.ClientRandom)

	_, f := this.masterSecrets[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}

	// TODO 保存多个lable 整组里？？？
	// save to file
	//var b *bytes.Buffer
	//l, e := this.keylogger.WriteString(b.String())
	//if e != nil {
	//	this.logger.Fatalf("%s: save masterSecrets to file error:%s", secretEvent.String(), e.Error())
	//	return
	//}

	//
	this.logger.Printf("%s: save masterSecrets %02x to file success, %d bytes", secretEvent.String(), secretEvent.ClientRandom, len(secretEvent.String()))
	/*
		switch this.eBPFProgramType {
		case EbpfprogramtypeOpensslTc:
			e = this.savePcapngSslKeyLog(b.Bytes())
			if e != nil {
				this.logger.Fatalf("%s: save masterSecrets to pcapng error:%s", secretEvent.String(), e.Error())
				return
			}
		default:
		}
	*/
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
