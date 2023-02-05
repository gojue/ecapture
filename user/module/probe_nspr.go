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

type MNsprProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (this *MNsprProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MNsprProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MNsprProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = this.geteBPFName("user/bytecode/nspr_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename:%s\n", this.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v .", err)
	}

	// setup the managers
	err = this.setupManagers()
	if err != nil {
		return fmt.Errorf("tls module couldn't find binPath %v ", err)
	}

	// initialize the bootstrap manager
	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v ", err)
	}

	// start the bootstrap manager
	if err := this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v ", err)
	}

	// 加载map信息，map对应events decode表。
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MNsprProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v ", err)
	}
	return this.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (this *MNsprProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(this.conf.GetPid()),
		},
	}

	if this.conf.GetPid() <= 0 {
		this.logger.Printf("%s\ttarget all process. \n", this.Name())
	} else {
		this.logger.Printf("%s\ttarget PID:%d \n", this.Name(), this.conf.GetPid())
	}
	return editor
}

func (this *MNsprProbe) setupManagers() error {
	var binaryPath string
	switch this.conf.(*config.NsprConfig).ElfType {
	case config.ELF_TYPE_BIN:
		binaryPath = this.conf.(*config.NsprConfig).Firefoxpath
	case config.ELF_TYPE_SO:
		binaryPath = this.conf.(*config.NsprConfig).Nsprpath
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libnspr4.so"
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	this.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", this.Name(), this.conf.(*config.NsprConfig).ElfType, binaryPath)

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/PR_Write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "PR_Write",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/PR_Write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "PR_Write",
				BinaryPath:       binaryPath,
			},

			// for PR_Send start
			//  |  ``PR_Send`` or ``PR_Write``
			//   | ``PR_Read`` or ``PR_Recv``
			{
				UID:              "PR_Write-PR_Send",
				Section:          "uprobe/PR_Write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "PR_Send",
				BinaryPath:       binaryPath,
			},
			{
				UID:              "PR_Write-PR_Send",
				Section:          "uretprobe/PR_Write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "PR_Send",
				BinaryPath:       binaryPath,
			},
			// for PR_Send end

			{
				Section:          "uprobe/PR_Read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "PR_Read",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/PR_Read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "PR_Read",
				BinaryPath:       binaryPath,
			},

			{
				UID:              "PR_Read-PR_Recv",
				Section:          "uprobe/PR_Read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "PR_Recv",
				BinaryPath:       binaryPath,
			},
			{
				UID:              "PR_Read-PR_Recv",
				Section:          "uretprobe/PR_Read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "PR_Recv",
				BinaryPath:       binaryPath,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "nspr_events",
			},
		},
	}

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

	if this.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		this.bpfManagerOptions.ConstantEditors = this.constantEditor()
	}
	return nil
}

func (this *MNsprProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MNsprProbe) initDecodeFun() error {
	// NsprEventsMap 与解码函数映射
	NsprEventsMap, found, err := this.bpfManager.GetMap("nspr_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:nspr_events")
	}
	this.eventMaps = append(this.eventMaps, NsprEventsMap)
	this.eventFuncMaps[NsprEventsMap] = &event.NsprDataEvent{}

	return nil
}

func (this *MNsprProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MNsprProbe{}
	mod.name = MODULE_NAME_NSPR
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
