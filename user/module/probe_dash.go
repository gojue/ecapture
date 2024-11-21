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
	"io"
	"math"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/rs/zerolog"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

const (
	DashEventTypeReadline = 0
)

type MDashProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (b *MDashProbe) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, ecw io.Writer) error {
	err := b.Module.Init(ctx, logger, conf, ecw)
	if err != nil {
		return err
	}
	b.conf = conf
	b.Module.SetChild(b)
	b.eventMaps = make([]*ebpf.Map, 0, 2)
	b.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (b *MDashProbe) Start() error {
	if err := b.start(); err != nil {
		return err
	}
	return nil
}

func (b *MDashProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = b.geteBPFName("user/bytecode/dash_kern.o")
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

func (b *MDashProbe) Close() error {
	if err := b.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v ", err)
	}
	return b.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (b *MDashProbe) constantEditor() []manager.ConstantEditor {
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
			Value: uint64(b.Module.conf.(*config.DashConfig).ErrNo),
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

func calReadFuncAddressByGDB(elfPath string) (uint64, error) {

	cmd := fmt.Sprintf("%s %s --batch -ex 'printf \"%%p\", %s'", elfPath, "/bin/dash", "read")
	out, err := exec.Command("/bin/sh", "-c", cmd).Output()
	if err != nil {
		return 0, err
	}
	hexStr := strings.TrimSpace(string(out))
	output := strings.TrimPrefix(hexStr, "0x")
	ui64, err := strconv.ParseUint(output, 16, 64)
	if err != nil {
		return 0, err
	}
	return ui64, nil
}

func calReadFuncAddressByObjdump(elfPath string) (uint64, error) {
	//0000000000005800 <read@plt>:
	cmd := fmt.Sprintf("%s -d /bin/dash | grep read@plt | head -n 1", elfPath)
	out, err := exec.Command("/bin/sh", "-c", cmd).Output()
	if err != nil {
		return 0, err
	}
	outputStr := strings.TrimSpace(string(out))
	split := strings.Split(outputStr, " ")
	if len(split) < 1 {
		return 0, fmt.Errorf("objdump not expected result:%s", outputStr)
	}
	output := strings.TrimPrefix(split[0], "0")
	ui64, err := strconv.ParseUint(output, 16, 64)
	if err != nil {
		return 0, err
	}
	return ui64, nil
}
func (b *MDashProbe) calReadFuncAddress() (uint64, error) {

	var findElfBinErr, runCommandErr error
	var elfPath string
	var addr uint64
	if elfPath, findElfBinErr = exec.LookPath("gdb"); findElfBinErr == nil {
		if addr, runCommandErr = calReadFuncAddressByGDB(elfPath); runCommandErr == nil {
			return addr, nil
		}
	}
	//zap.S().Warnf("calReadFuncAddressByGDB failed,findElfBinErr:%v,runCommandErr:%v", findElfBinErr, runCommandErr)
	if elfPath, findElfBinErr = exec.LookPath("objdump"); findElfBinErr == nil {
		if addr, runCommandErr = calReadFuncAddressByObjdump(elfPath); runCommandErr == nil {
			return addr, nil
		}
	}
	//zap.S().Warnf("calReadFuncAddressByObjdump failed,findElfBinErr:%v,runCommandErr:%v", findElfBinErr, runCommandErr)

	return 0, errors.New("use gdb and objdump to calReadFuncAddress failed")
}

func (b *MDashProbe) setupManagers() {
	var binaryPath string
	switch b.conf.(*config.DashConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = b.conf.(*config.DashConfig).Dashpath
	case config.ElfTypeSo:
		binaryPath = b.conf.(*config.DashConfig).Readline
	default:
		binaryPath = "/bin/dash"
	}

	var readlineFuncName string // 将默认hook函数改为readline_internal_teardown说明：https://github.com/gojue/ecapture/pull/479
	readlineFuncName = b.conf.(*config.DashConfig).ReadlineFuncName
	addr, err := b.calReadFuncAddress()
	if err != nil {
		b.logger.Info().Msg("calc error")
		return
	}
	b.logger.Info().Msg("calc success")
	b.logger.Info().Str("binaryPath", binaryPath).Str("readlineFuncName", readlineFuncName).
		Str("execute_command", readlineFuncName).Str("exit_builtin", readlineFuncName).
		Str("exec_builtin", readlineFuncName).Msg("Hook Info")
	b.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/dash_read",
				EbpfFuncName:     "uprobe_dash_read",
				AttachToFuncName: readlineFuncName,
				UAddress:         addr,
				//UAddress:         0x3860,     //若找不到 readline 函数，则使用offset偏移地址方式。
				BinaryPath: binaryPath, // 可能是 /bin/dash 也可能是 readline.so的真实地址
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

func (b *MDashProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := b.eventFuncMaps[em]
	return fun, found
}

func (b *MDashProbe) initDecodeFun() error {
	//dashEventsMap 与解码函数映射
	dashEventsMap, found, err := b.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	b.eventMaps = append(b.eventMaps, dashEventsMap)
	dashevent := &event.DashEvent{}
	//dashevent.SetModule(b)
	b.eventFuncMaps[dashEventsMap] = dashevent

	return nil
}

func (b *MDashProbe) Events() []*ebpf.Map {
	return b.eventMaps
}

func (b *MDashProbe) Dispatcher(eventStruct event.IEventStruct) {
	be, ok := eventStruct.(*event.DashEvent)
	if !ok {
		return
	}
	b.handleLine(be)
}

func (b *MDashProbe) handleLine(be *event.DashEvent) {
	_, _ = b.eventCollector.Write([]byte(be.String()))
}

func init() {
	RegisteFunc(NewDashProbe)
}

func NewDashProbe() IModule {
	mod := &MDashProbe{}
	mod.name = ModuleNameDash
	mod.mType = ProbeTypeUprobe
	return mod
}
