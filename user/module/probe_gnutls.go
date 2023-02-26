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

type MGnutlsProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (this *MGnutlsProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *MGnutlsProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MGnutlsProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = this.geteBPFName("user/bytecode/gnutls_kern.o")
	this.logger.Printf("%s\tBPF bytecode filename:%s\n", this.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return fmt.Errorf("couldn't find asset %v", err)
	}

	// setup the managers
	err = this.setupManagers()
	if err != nil {
		return fmt.Errorf("tls(gnutls) module couldn't find binPath %v", err)
	}

	// initialize the bootstrap manager
	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	// 加载map信息，map对应events decode表。
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MGnutlsProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v", err)
	}
	return this.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (this *MGnutlsProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(this.conf.GetPid()),
			//FailOnMissing: true,
		},
	}

	if this.conf.GetPid() <= 0 {
		this.logger.Printf("%s\ttarget all process. \n", this.Name())
	} else {
		this.logger.Printf("%s\ttarget PID:%d \n", this.Name(), this.conf.GetPid())
	}
	return editor
}

func (this *MGnutlsProbe) setupManagers() error {
	var binaryPath string
	switch this.conf.(*config.GnutlsConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = this.conf.(*config.GnutlsConfig).Curlpath
	case config.ElfTypeSo:
		binaryPath = this.conf.(*config.GnutlsConfig).Gnutls
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libgnutls.so.30"
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	this.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", this.Name(), this.conf.(*config.GnutlsConfig).ElfType, binaryPath)

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/gnutls_record_send",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "gnutls_record_send",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/gnutls_record_send",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "gnutls_record_send",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uprobe/gnutls_record_recv",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "gnutls_record_recv",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/gnutls_record_recv",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "gnutls_record_recv",
				BinaryPath:       binaryPath,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "gnutls_events",
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

func (this *MGnutlsProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MGnutlsProbe) initDecodeFun() error {
	//GnutlsEventsMap 与解码函数映射
	GnutlsEventsMap, found, err := this.bpfManager.GetMap("gnutls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:gnutls_events")
	}
	this.eventMaps = append(this.eventMaps, GnutlsEventsMap)
	this.eventFuncMaps[GnutlsEventsMap] = &event.GnutlsDataEvent{}

	return nil
}

func (this *MGnutlsProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MGnutlsProbe{}
	mod.name = ModuleNameGnutls
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
