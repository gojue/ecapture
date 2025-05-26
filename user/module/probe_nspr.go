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
	"os"
	"path"
	"strings"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
)

type MNsprProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (n *MNsprProbe) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, ecw io.Writer) error {
	err := n.Module.Init(ctx, logger, conf, ecw)
	if err != nil {
		return err
	}
	n.conf = conf
	n.Module.SetChild(n)
	n.eventMaps = make([]*ebpf.Map, 0, 2)
	n.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (n *MNsprProbe) Start() error {
	if err := n.start(); err != nil {
		return err
	}
	return nil
}

func (n *MNsprProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = n.geteBPFName("user/bytecode/nspr_kern.o")
	n.logger.Info().Str("bpfFileName", bpfFileName).Msg("BPF bytecode file is matched.")
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		n.logger.Error().Err(err).Strs("bytecode files", assets.AssetNames()).Msg("couldn't find bpf bytecode file")
		return fmt.Errorf("couldn't find asset %v .", err)
	}

	// setup the managers
	err = n.setupManagers()
	if err != nil {
		return fmt.Errorf("tls module couldn't find binPath %v ", err)
	}

	// initialize the bootstrap manager
	if err = n.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), n.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v ", err)
	}

	// start the bootstrap manager
	if err := n.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v ", err)
	}

	// 加载map信息，map对应events decode表。
	err = n.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (n *MNsprProbe) Close() error {
	if err := n.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v ", err)
	}
	return n.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (n *MNsprProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(n.conf.GetPid()),
		},
		{
			Name:  "target_uid",
			Value: uint64(n.conf.GetUid()),
		},
	}

	if n.conf.GetPid() <= 0 {
		n.logger.Info().Msg("target all process.")
	} else {
		n.logger.Info().Uint64("target PID", n.conf.GetPid()).Msg("target process.")
	}
	if n.conf.GetUid() <= 0 {
		n.logger.Info().Msg("target all users.")
	} else {
		n.logger.Info().Uint64("target UID", n.conf.GetUid()).Msg("target user.")
	}
	return editor
}

func (n *MNsprProbe) setupManagers() error {
	var binaryPath string
	switch n.conf.(*config.NsprConfig).ElfType {
	//case config.ElfTypeBin:
	//	binaryPath = n.conf.(*config.NsprConfig).Firefoxpath
	case config.ElfTypeSo:
		binaryPath = n.conf.(*config.NsprConfig).Nsprpath
	default:
		//如果没找到
		binaryPath = path.Join(defaultSoPath, "libnspr4.so")
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	n.logger.Info().Str("binrayPath", binaryPath).Uint8("ElfType", n.conf.(*config.NsprConfig).ElfType).Msg("HOOK type:nspr elf")
	if strings.Contains(binaryPath, "libnss3.so") || strings.Contains(binaryPath, "libnss.so") {
		n.logger.Warn().Msg("In normal circumstances, the PR_Write/PR_Read functions should be in libnspr4.so. If it fails to run, please try specifying the --nspr=/xxx/libnspr4.so path. ")
		n.logger.Warn().Msg("For more information, please refer to https://github.com/gojue/ecapture/issues/662 .")
	}
	n.bpfManager = &manager.Manager{
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

	n.bpfManagerOptions = manager.Options{
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

	if n.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		n.bpfManagerOptions.ConstantEditors = n.constantEditor()
	}
	return nil
}

func (n *MNsprProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := n.eventFuncMaps[em]
	return fun, found
}

func (n *MNsprProbe) initDecodeFun() error {
	// NsprEventsMap 与解码函数映射
	NsprEventsMap, found, err := n.bpfManager.GetMap("nspr_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:nspr_events")
	}
	n.eventMaps = append(n.eventMaps, NsprEventsMap)
	n.eventFuncMaps[NsprEventsMap] = &event.NsprDataEvent{}

	return nil
}

func (n *MNsprProbe) Events() []*ebpf.Map {
	return n.eventMaps
}

func init() {
	RegisteFunc(NewNsprProbe)
}

func NewNsprProbe() IModule {
	mod := &MNsprProbe{}
	mod.name = ModuleNameNspr
	mod.mType = ProbeTypeUprobe
	return mod
}
