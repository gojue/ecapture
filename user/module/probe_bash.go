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
	"errors"
	"fmt"
	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/rs/zerolog"
	"io"
	"math"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

const (
	BashEventTypeReadline   = 0
	BashEventTypeRetval     = 1
	BashEventTypeExitOrExec = 2
)

type MBashProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
	lineMap           map[string]string
}

// 对象初始化
func (b *MBashProbe) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, ecw io.Writer) error {
	err := b.Module.Init(ctx, logger, conf, ecw)
	if err != nil {
		return err
	}
	b.conf = conf
	b.Module.SetChild(b)
	b.eventMaps = make([]*ebpf.Map, 0, 2)
	b.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	b.lineMap = make(map[string]string)
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
	b.logger.Info().Str("bpfFileName", bpfFileName).Msg("BPF bytecode file is matched.")
	byteBuf, err := assets.Asset(bpfFileName)

	if err != nil {
		b.logger.Error().Err(err).Strs("bytecode files", assets.AssetNames()).Msg("couldn't find bpf bytecode file")
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
		b.logger.Info().Msg("target all process.")
	} else {
		b.logger.Info().Uint64("target PID", b.conf.GetPid()).Send()
	}

	if b.conf.GetUid() <= 0 {
		b.logger.Info().Msg("target all users.")
	} else {
		b.logger.Info().Uint64("target UID", b.conf.GetUid()).Send()
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

	var readlineFuncName string // 将默认hook函数改为readline_internal_teardown说明：https://github.com/gojue/ecapture/pull/479
	readlineFuncName = b.conf.(*config.BashConfig).ReadlineFuncName

	b.logger.Info().Str("binaryPath", binaryPath).Str("readlineFuncName", readlineFuncName).
		Str("execute_command", readlineFuncName).Str("exit_builtin", readlineFuncName).
		Str("exec_builtin", readlineFuncName).Msg("Hook Info")
	b.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uretprobe/bash_readline",
				EbpfFuncName:     "uretprobe_bash_readline",
				AttachToFuncName: readlineFuncName,
				//UprobeOffset: 0x8232, 	//若找不到 readline 函数，则使用offset偏移地址方式。
				BinaryPath: binaryPath, // 可能是 /bin/bash 也可能是 readline.so的真实地址
			},
			{
				Section:          "uretprobe/bash_retval",
				EbpfFuncName:     "uretprobe_bash_retval",
				AttachToFuncName: "execute_command",
				BinaryPath:       binaryPath, // 可能是 /bin/bash 也可能是 readline.so的真实地址
			},
			{
				Section:          "uprobe/exec_builtin",
				EbpfFuncName:     "uprobe_exec_builtin",
				AttachToFuncName: "exec_builtin",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uprobe/exit_builtin",
				EbpfFuncName:     "uprobe_exit_builtin",
				AttachToFuncName: "exit_builtin",
				BinaryPath:       binaryPath,
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

func (b *MBashProbe) Dispatcher(eventStruct event.IEventStruct) {
	be, ok := eventStruct.(*event.BashEvent)
	if !ok {
		return
	}
	b.handleLine(be)
}

func (b *MBashProbe) handleLine(be *event.BashEvent) {
	switch be.BashType {
	case BashEventTypeReadline:
		newline := unix.ByteSliceToString((be.Line[:]))
		line := b.lineMap[be.GetUUID()]
		if line != "" {
			line += "\n" + newline
		} else {
			line += newline
		}
		b.lineMap[be.GetUUID()] = line
		return
	case BashEventTypeRetval:
		line := b.lineMap[be.GetUUID()]
		delete(b.lineMap, be.GetUUID())
		if line == "" || be.ReturnValue == uint32(BashErrnoDefault) {
			return
		}
		be.AllLines = line
	case BashEventTypeExitOrExec:
		line := b.lineMap[be.GetUUID()]
		delete(b.lineMap, be.GetUUID())
		if line == "" {
			return
		}
		be.ReturnValue = BashEventTypeExitOrExec // we do not know the return value here
		be.AllLines = line
	default:
		return
	}
	if b.conf.GetHex() {
		//b.logger.Println(be.StringHex())
		_, _ = b.eventCollector.Write([]byte(be.StringHex()))
	} else {
		//b.logger.Println(be.String())
		_, _ = b.eventCollector.Write([]byte(be.String()))
	}
}

func init() {
	RegisteFunc(NewBashProbe)
}

func NewBashProbe() IModule {
	mod := &MBashProbe{}
	mod.name = ModuleNameBash
	mod.mType = ProbeTypeUprobe
	return mod
}
