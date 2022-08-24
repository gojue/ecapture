//go:build !androidgki
// +build !androidgki

/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package module

import (
	"bytes"
	"context"
	"ecapture/assets"
	"ecapture/user/config"
	"ecapture/user/event"
	"fmt"
	"log"
	"math"
	"os"

	"errors"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
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
func (this *MPostgresProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MPostgresProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MPostgresProbe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/postgres_kern.o")
	if err != nil {
		return fmt.Errorf("couldn't find asset")
	}

	// setup the managers
	err = this.setupManagers()
	if err != nil {
		return fmt.Errorf("postgres module couldn't find binPath %v.", err)
	}

	// initialize the bootstrap manager
	if err := this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v.", err)
	}

	// start the bootstrap manager
	if err := this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v.", err)
	}

	// 加载map信息，map对应events decode表。
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MPostgresProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v.", err)
	}
	return this.Module.Close()
}

func (this *MPostgresProbe) setupManagers() error {
	binaryPath := this.conf.(*config.PostgresConfig).PostgresPath

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}
	attachFunc := this.conf.(*config.PostgresConfig).FuncName

	probes := []*manager.Probe{
		{
			Section:          "uprobe/exec_simple_qurey",
			EbpfFuncName:     "postgres_query",
			AttachToFuncName: attachFunc,
			BinaryPath:       binaryPath,
		},
	}

	this.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	this.logger.Printf("Postgres, binrayPath: %s, FunctionName: %s\n", binaryPath, attachFunc)

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
	return nil
}

func (this *MPostgresProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MPostgresProbe) initDecodeFun() error {
	// postgresEventsMap to hook
	postgresEventsMap, found, err := this.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map: events")
	}
	this.eventMaps = append(this.eventMaps, postgresEventsMap)
	this.eventFuncMaps[postgresEventsMap] = &event.PostgresEvent{}

	return nil
}

func (this *MPostgresProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MPostgresProbe{}
	mod.name = MODULE_NAME_POSTGRES
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
