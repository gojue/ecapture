//go:build !androidgki
// +build !androidgki

// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
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
	"fmt"
	"io"
	"math"
	"os"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/rs/zerolog"

	"errors"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type MPostgresProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// init probe
func (p *MPostgresProbe) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, ecw io.Writer) error {
	err := p.Module.Init(ctx, logger, conf, ecw)
	if err != nil {
		return err
	}
	p.conf = conf
	p.Module.SetChild(p)
	p.eventMaps = make([]*ebpf.Map, 0, 2)
	p.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (p *MPostgresProbe) Start() error {
	if err := p.start(); err != nil {
		return err
	}
	return nil
}

func (p *MPostgresProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = p.geteBPFName("user/bytecode/postgres_kern.o")
	p.logger.Info().Str("bpfFileName", bpfFileName).Msg("BPF bytecode file is matched.")

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		p.logger.Error().Err(err).Strs("bytecode files", assets.AssetNames()).Msg("couldn't find bpf bytecode file")
		return fmt.Errorf("couldn't find asset")
	}

	// setup the managers
	err = p.setupManagers()
	if err != nil {
		return fmt.Errorf("postgres module couldn't find binPath %v.", err)
	}

	// initialize the bootstrap manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), p.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v.", err)
	}

	// start the bootstrap manager
	if err := p.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v.", err)
	}

	// 加载map信息，map对应events decode表。
	err = p.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (p *MPostgresProbe) Close() error {
	if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v.", err)
	}
	return p.Module.Close()
}

func (p *MPostgresProbe) setupManagers() error {
	binrayPath := p.conf.(*config.PostgresConfig).PostgresPath

	_, err := os.Stat(binrayPath)
	if err != nil {
		return err
	}
	attachFunc := p.conf.(*config.PostgresConfig).FuncName

	probes := []*manager.Probe{
		{
			Section:          "uprobe/exec_simple_query",
			EbpfFuncName:     "postgres_query",
			AttachToFuncName: attachFunc,
			BinaryPath:       binrayPath,
		},
	}

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	p.logger.Info().Str("binrayPath", binrayPath).Str("Function", attachFunc).Msg("Postgres probe setup")

	p.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSizeStart: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
	return nil
}

func (p *MPostgresProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

func (p *MPostgresProbe) initDecodeFun() error {
	// postgresEventsMap to hook
	postgresEventsMap, found, err := p.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map: events")
	}
	p.eventMaps = append(p.eventMaps, postgresEventsMap)
	p.eventFuncMaps[postgresEventsMap] = &event.PostgresEvent{}

	return nil
}

func (p *MPostgresProbe) Events() []*ebpf.Map {
	return p.eventMaps
}

func init() {
	RegisteFunc(NewPostgresProbe)
}

func NewPostgresProbe() IModule {
	mod := &MPostgresProbe{}
	mod.name = ModuleNamePostgres
	mod.mType = ProbeTypeUprobe
	return mod
}
