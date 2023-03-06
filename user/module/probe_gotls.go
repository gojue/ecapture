// Copyright © 2022 Hengqi Chen
package module

import (
	"bytes"
	"context"
	"ecapture/assets"
	"ecapture/pkg/proc"
	"ecapture/user/config"
	"ecapture/user/event"
	"log"
	"math"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

func init() {
	mod := &GoTLSProbe{}
	Register(mod)
}

const (
	goTlsHookFunc      = "crypto/tls.(*Conn).writeRecordLocked"
	goTlsMasterKeyFunc = "crypto/tls.(*Config).writeKeyLog"
)

// GoTLSProbe represents a probe for Go SSL
type GoTLSProbe struct {
	Module
	MTCProbe
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
	path              string
	isRegisterABI     bool
}

func (this *GoTLSProbe) Init(ctx context.Context, l *log.Logger, cfg config.IConfig) error {
	this.Module.Init(ctx, l, cfg)
	this.conf = cfg
	this.Module.SetChild(this)

	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	this.path = cfg.(*config.GoTLSConfig).Path
	ver, err := proc.ExtraceGoVersion(this.path)
	if err != nil {
		return err
	}

	// supported at 1.17 via https://github.com/golang/go/issues/40724
	if ver.After(1, 17) {
		this.isRegisterABI = true
	}
	return nil
}

func (this *GoTLSProbe) Name() string {
	return ModuleNameGotls
}

func (this *GoTLSProbe) Start() error {
	var (
		sec string
		fn  string
	)

	if this.isRegisterABI {
		sec = "uprobe/gotls_text_register"
		fn = "gotls_text_register"
	} else {
		sec = "uprobe/gotls_text_stack"
		fn = "gotls_text_stack"
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

			//{
			//	Section:          "uprobe/gotls_masterkey",
			//	EbpfFuncName:     "gotls_masterkey",
			//	AttachToFuncName: "crypto/tls.(*Conn).writeRecordLocked",
			//	BinaryPath:       this.path,
			//},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	// crypto/tls.(*Config).writeKeyLog
	// crypto/tls/common.go
	/*
		func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
		}
	*/

	var bpfFileName = this.geteBPFName("user/bytecode/gotls_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename:%s\n", this.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return err
	}

	opts := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
	if err := this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), opts); err != nil {
		return err
	}

	return this.bpfManager.Start()
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
			Value: uint64(this.conf.(*config.OpensslConfig).Port),
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

func (this *GoTLSProbe) Events() []*ebpf.Map {
	var maps []*ebpf.Map

	m, ok, err := this.bpfManager.GetMap("events")
	if err != nil || !ok {
		return maps
	}

	maps = append(maps, m)
	return maps
}

func (this *GoTLSProbe) DecodeFun(m *ebpf.Map) (event.IEventStruct, bool) {
	return &event.GoTLSEvent{}, true
}

func (this *GoTLSProbe) Close() error {
	return this.Module.Close()
}
