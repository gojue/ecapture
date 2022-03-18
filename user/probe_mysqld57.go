/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"bytes"
	"context"
	"ecapture/assets"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"log"
	"math"
)

type MMysqld57Probe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
	conf              IConfig
}

//对象初始化
func (this *MMysqld57Probe) Init(ctx context.Context, logger *log.Logger, conf IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MMysqld57Probe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MMysqld57Probe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/mysqld57_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	this.setupManagers()

	// initialize the bootstrap manager
	if err := this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := this.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MMysqld57Probe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (this *MMysqld57Probe) setupManagers() {
	var binaryPath string

	binaryPath = "/usr/sbin/mariadbd"

	// mariadbd version : 10.5.13-MariaDB-0ubuntu0.21.04.1
	// objdump -T /usr/sbin/mariadbd |grep dispatch_command
	// 0000000000710410 g    DF .text	0000000000002f35  Base        _Z16dispatch_command19enum_server_commandP3THDPcjbb
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/dispatch_command",
				EbpfFuncName:     "query_start",
				AttachToFuncName: "_Z16dispatch_command19enum_server_commandP3THDPcjbb",
				//UprobeOffset:     0x710410,
				BinaryPath: binaryPath,
			},
			{
				Section:          "uretprobe/dispatch_command",
				EbpfFuncName:     "query_end",
				AttachToFuncName: "_Z16dispatch_command19enum_server_commandP3THDPcjbb",
				//UprobeOffset:     0x710410,
				BinaryPath: binaryPath,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	this.logger.Printf("HOOK binrayPath:%s, UprobeOffset:0x710410\n", binaryPath)

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
}

func (this *MMysqld57Probe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MMysqld57Probe) initDecodeFun() error {
	// mysqld57EventsMap 与解码函数映射
	mysqld57EventsMap, found, err := this.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, mysqld57EventsMap)
	this.eventFuncMaps[mysqld57EventsMap] = &mysqld57Event{}

	return nil
}

func (this *MMysqld57Probe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MMysqld57Probe{}
	mod.name = MODULE_NAME_MYSQLD57
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
