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
	manager "github.com/ehids/ebpfmanager"
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

func (p *GoSSLProbe) Init(ctx context.Context, l *log.Logger, cfg config.IConfig) error {
	p.Module.Init(ctx, l, cfg)
	p.Module.SetChild(p)

	p.path = cfg.(*config.GoSSLConfig).Path
	ver, err := proc.ExtraceGoVersion(p.path)
	if err != nil {
		return err
	}

	if ver.After(1, 15) {
		p.isRegisterABI = true
	}
	return nil
}

func (p *GoSSLProbe) Name() string {
	return MODULE_NAME_GOSSL
}

func (p *GoSSLProbe) Start() error {
	var (
		sec string
		fn  string
	)

	if p.isRegisterABI {
		sec = "uprobe/abi_register"
		fn = "probe_register"
	} else {
		sec = "uprobe/abi_stack"
		fn = "probe_stack"
	}

	p.mngr = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: "crypto/tls.(*Conn).writeRecordLocked",
				BinaryPath:       p.path,
			},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	data, err := assets.Asset("user/bytecode/gossl_kern.o")
	if err != nil {
		return err
	}

	opts := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
	if err := p.mngr.InitWithOptions(bytes.NewReader(data), opts); err != nil {
		return err
	}

	return p.mngr.Start()
}

func (p *GoSSLProbe) Events() []*ebpf.Map {
	var maps []*ebpf.Map

	m, ok, err := p.mngr.GetMap("events")
	if err != nil || !ok {
		return maps
	}

	maps = append(maps, m)
	return maps
}

func (p *GoSSLProbe) DecodeFun(m *ebpf.Map) (event.IEventStruct, bool) {
	return &event.GoSSLEvent{}, true
}

func (p *GoSSLProbe) Close() error {
	return p.Module.Close()
}
