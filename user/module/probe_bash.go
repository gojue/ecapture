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
)

type MBashProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (b *MBashProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	b.Module.Init(ctx, logger, conf)
	b.conf = conf
	b.Module.SetChild(b)
	b.eventMaps = make([]*ebpf.Map, 0, 2)
	b.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (b *MBashProbe) Start() error {
	if err := b.start(); err != nil {
		return err
	}
	return nil
}

func (b *MBashProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = b.geteBPFName("user/bytecode/bash_kern.o")
	b.logger.Printf("%s\tBPF bytecode filename:%s\n", b.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v", err)
	}

	// setup the managers
	b.setupManagers()

	// initialize the bootstrap manager
	if err = b.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), b.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v ", err)
	}

	// start the bootstrap manager
	if err = b.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v ", err)
	}

	// 加载map信息，map对应events decode表。
	err = b.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (b *MBashProbe) Close() error {
	if err := b.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v ", err)
	}
	return b.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (b *MBashProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(b.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(b.conf.GetUid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_errno",
			Value: uint64(b.Module.conf.(*config.BashConfig).ErrNo),
		},
	}

	if b.conf.GetPid() <= 0 {
		b.logger.Printf("%s\ttarget all process. \n", b.Name())
	} else {
		b.logger.Printf("%s\ttarget PID:%d \n", b.Name(), b.conf.GetPid())
	}

	if b.conf.GetUid() <= 0 {
		b.logger.Printf("%s\ttarget all users. \n", b.Name())
	} else {
		b.logger.Printf("%s\ttarget UID:%d \n", b.Name(), b.conf.GetUid())
	}

	return editor
}

func (b *MBashProbe) setupManagers() {
	var binaryPath string
	switch b.conf.(*config.BashConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = b.conf.(*config.BashConfig).Bashpath
	case config.ElfTypeSo:
		binaryPath = b.conf.(*config.BashConfig).Readline
	default:
		binaryPath = "/bin/bash"
	}

	b.logger.Printf("%s\tHOOK binrayPath:%s, FunctionName:readline\n", b.Name(), binaryPath)
	b.logger.Printf("%s\tHOOK binrayPath:%s, FunctionName:execute_command\n", b.Name(), binaryPath)

	b.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uretprobe/bash_readline",
				EbpfFuncName:     "uretprobe_bash_readline",
				AttachToFuncName: "readline",
				//UprobeOffset: 0x8232, 	//若找不到 readline 函数，则使用offset便宜地址方式。
				BinaryPath: binaryPath, // 可能是 /bin/bash 也可能是 readline.so的真实地址
			},
			{
				Section:          "uretprobe/bash_retval",
				EbpfFuncName:     "uretprobe_bash_retval",
				AttachToFuncName: "execute_command",
				BinaryPath:       binaryPath, // 可能是 /bin/bash 也可能是 readline.so的真实地址
			},
		},

		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	b.bpfManagerOptions = manager.Options{
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

	if b.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		b.bpfManagerOptions.ConstantEditors = b.constantEditor()
	}

}

func (b *MBashProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := b.eventFuncMaps[em]
	return fun, found
}

func (b *MBashProbe) initDecodeFun() error {
	//bashEventsMap 与解码函数映射
	bashEventsMap, found, err := b.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	b.eventMaps = append(b.eventMaps, bashEventsMap)
	bashevent := &event.BashEvent{}
	//bashevent.SetModule(b)
	b.eventFuncMaps[bashEventsMap] = bashevent

	return nil
}

func (b *MBashProbe) Events() []*ebpf.Map {
	return b.eventMaps
}

func init() {
	mod := &MBashProbe{}
	mod.name = ModuleNameBash
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
