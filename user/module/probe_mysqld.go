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
	"ecapture/assets"
	"ecapture/user/config"
	"ecapture/user/event"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
	"log"
	"math"
	"os"
)

type MMysqldProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (m *MMysqldProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	m.Module.Init(ctx, logger, conf)
	m.conf = conf
	m.Module.SetChild(m)
	m.eventMaps = make([]*ebpf.Map, 0, 2)
	m.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (m *MMysqldProbe) Start() error {
	if err := m.start(); err != nil {
		return err
	}
	return nil
}

func (m *MMysqldProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = m.geteBPFName("user/bytecode/mysqld_kern.o")
	m.logger.Printf("%s\tBPF bytecode filename:%s\n", m.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	// setup the managers
	err = m.setupManagers()
	if err != nil {
		return fmt.Errorf("mysqld module couldn't find binPath %v.", err)
	}

	// initialize the bootstrap manager
	if err = m.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), m.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = m.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	// 加载map信息，map对应events decode表。
	err = m.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (m *MMysqldProbe) Close() error {
	if err := m.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return m.Module.Close()
}

func (m *MMysqldProbe) setupManagers() error {
	var binaryPath string
	switch m.conf.(*config.MysqldConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = m.conf.(*config.MysqldConfig).Mysqldpath
	default:
		//如果没找到
		binaryPath = "/usr/sbin/mariadbd"
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}
	attachFunc := m.conf.(*config.MysqldConfig).FuncName
	offset := m.conf.(*config.MysqldConfig).Offset
	version := m.conf.(*config.MysqldConfig).Version
	versionInfo := m.conf.(*config.MysqldConfig).VersionInfo

	// mariadbd version : 10.5.13-MariaDB-0ubuntu0.21.04.1
	// objdump -T /usr/sbin/mariadbd |grep dispatch_command
	// 0000000000710410 g    DF .text	0000000000002f35  Base        _Z16dispatch_command19enum_server_commandP3THDPcjbb
	// offset 0x710410
	var probes []*manager.Probe
	switch version {
	case config.MysqldType57:
		probes = []*manager.Probe{
			{
				Section:          "uprobe/dispatch_command_57",
				EbpfFuncName:     "mysql57_query",
				AttachToFuncName: attachFunc,
				UprobeOffset:     offset,
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/dispatch_command_57",
				EbpfFuncName:     "mysql57_query_return",
				AttachToFuncName: attachFunc,
				UprobeOffset:     offset,
				BinaryPath:       binaryPath,
			},
		}
	case config.MysqldType80:
		probes = []*manager.Probe{
			{
				Section:          "uprobe/dispatch_command_57", //TODO CHANGE to mysqld80 @CFC4N
				EbpfFuncName:     "mysql57_query",
				AttachToFuncName: attachFunc,
				UprobeOffset:     offset,
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/dispatch_command_57",
				EbpfFuncName:     "mysql57_query_return",
				AttachToFuncName: attachFunc,
				UprobeOffset:     offset,
				BinaryPath:       binaryPath,
			},
		}
	default:
		probes = []*manager.Probe{
			{
				Section:          "uprobe/dispatch_command",
				EbpfFuncName:     "mysql56_query",
				AttachToFuncName: attachFunc,
				UprobeOffset:     offset,
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/dispatch_command",
				EbpfFuncName:     "mysql56_query_return",
				AttachToFuncName: attachFunc,
				UprobeOffset:     offset,
				BinaryPath:       binaryPath,
			},
		}
	}

	m.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	m.logger.Printf("%s\tMysql Version:%s, binrayPath:%s, FunctionName:%s ,UprobeOffset:%d\n", m.Name(), versionInfo, binaryPath, attachFunc, offset)

	m.bpfManagerOptions = manager.Options{
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

func (m *MMysqldProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := m.eventFuncMaps[em]
	return fun, found
}

func (m *MMysqldProbe) initDecodeFun() error {
	// mysqldEventsMap 与解码函数映射
	mysqldEventsMap, found, err := m.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	m.eventMaps = append(m.eventMaps, mysqldEventsMap)
	m.eventFuncMaps[mysqldEventsMap] = &event.MysqldEvent{}

	return nil
}

func (m *MMysqldProbe) Events() []*ebpf.Map {
	return m.eventMaps
}

func init() {
	mod := &MMysqldProbe{}
	mod.name = ModuleNameMysqld
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
