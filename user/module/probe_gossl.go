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
	mod := &GoSSLProbe{}
	Register(mod)
}

// GoSSLProbe represents a probe for Go SSL
type GoSSLProbe struct {
	Module

	mngr          *manager.Manager
	path          string
	isRegisterABI bool
}

func (this *GoSSLProbe) Init(ctx context.Context, l *log.Logger, cfg config.IConfig) error {
	this.Module.Init(ctx, l, cfg)
	this.conf = cfg
	this.Module.SetChild(this)

	this.path = cfg.(*config.GoSSLConfig).Path
	ver, err := proc.ExtraceGoVersion(this.path)
	if err != nil {
		return err
	}

	if ver.After(1, 15) {
		this.isRegisterABI = true
	}
	return nil
}

func (this *GoSSLProbe) Name() string {
	return MODULE_NAME_GOSSL
}

func (this *GoSSLProbe) Start() error {
	var (
		sec string
		fn  string
	)

	if this.isRegisterABI {
		sec = "uprobe/abi_register"
		fn = "probe_register"
	} else {
		sec = "uprobe/abi_stack"
		fn = "probe_stack"
	}

	this.mngr = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: "crypto/tls.(*Conn).writeRecordLocked",
				BinaryPath:       this.path,
			},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	var bpfFileName = this.geteBPFName("user/bytecode/gossl_kern.o")
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

func (this *GoSSLProbe) Events() []*ebpf.Map {
	var maps []*ebpf.Map

	m, ok, err := this.mngr.GetMap("events")
	if err != nil || !ok {
		return maps
	}

	maps = append(maps, m)
	return maps
}

func (this *GoSSLProbe) DecodeFun(m *ebpf.Map) (event.IEventStruct, bool) {
	return &event.GoSSLEvent{}, true
}

func (this *GoSSLProbe) Close() error {
	return this.Module.Close()
}
