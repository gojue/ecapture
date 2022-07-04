// Copyright © 2022 Hengqi Chen
package user

import (
	"bytes"
	"context"
	"ecapture/assets"
	"ecapture/pkg/event_processor"
	"ecapture/pkg/proc"
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
	gover         string
	isRegisterABI bool
}

func (p *GoSSLProbe) Init(ctx context.Context, l *log.Logger, cfg IConfig) error {
	p.Module.Init(ctx, l)
	p.Module.SetChild(p)

	var (
		ver *proc.GoVersion
		err error
	)

	p.path = cfg.(*GoSSLConfig).Path

	if len(cfg.(*GoSSLConfig).Gover) > 0 {
		p.gover = cfg.(*GoSSLConfig).Gover
		ver, err = proc.ParseGoVersion(p.gover)
		if err != nil {
			return err
		}

	} else {
		ver, err = proc.ExtraceGoVersion(p.path)
		if err != nil {
			return err
		}
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

func (p *GoSSLProbe) DecodeFun(m *ebpf.Map) (event_processor.IEventStruct, bool) {
	return &goSSLEvent{}, true
}

func (p *GoSSLProbe) Close() error {
	return nil
}
