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

// GoTLSProbe represents a probe for Go SSL
type GoTLSProbe struct {
	Module

	mngr          *manager.Manager
	path          string
	isRegisterABI bool
}

func (this *GoTLSProbe) Init(ctx context.Context, l *log.Logger, cfg config.IConfig) error {
	this.Module.Init(ctx, l, cfg)
	this.conf = cfg
	this.Module.SetChild(this)

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
	this.mngr = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: "crypto/tls.(*Conn).writeRecordLocked",
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
	if err := this.mngr.InitWithOptions(bytes.NewReader(byteBuf), opts); err != nil {
		return err
	}

	return this.mngr.Start()
}

func (this *GoTLSProbe) Events() []*ebpf.Map {
	var maps []*ebpf.Map

	m, ok, err := this.mngr.GetMap("events")
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
