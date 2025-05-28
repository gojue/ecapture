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
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
)

func (g *GoTLSProbe) setupManagersText() error {
	var (
		sec, readSec string
		fn, readFn   string
	)

	if g.isRegisterABI {
		sec = "uprobe/gotls_write_register"
		fn = "gotls_write_register"
		readSec = "uprobe/gotls_read_register"
		readFn = "gotls_read_register"
	} else {
		sec = "uprobe/gotls_write_stack"
		fn = "gotls_write_stack"
		readSec = "uprobe/gotls_read_stack"
		readFn = "gotls_read_stack"
	}
	var gotlsConf = g.conf.(*config.GoTLSConfig)
	var buildInfo = new(strings.Builder)
	for _, setting := range gotlsConf.Buildinfo.Settings {
		if setting.Value == "" {
			continue
		}
		buildInfo.WriteString(" ")
		buildInfo.WriteString(setting.Key)
		buildInfo.WriteString("=")
		buildInfo.WriteString(setting.Value)
	}
	g.logger.Info().Str("binrayPath", g.path).Bool("isRegisterABI", g.isRegisterABI).
		Str("GoVersion", gotlsConf.Buildinfo.GoVersion).
		Str("buildInfo", buildInfo.String()).Msg("HOOK type:Golang elf")
	if g.conf.(*config.GoTLSConfig).IsPieBuildMode {
		// buildmode pie is enabled.
		g.logger.Warn().Msg("Golang elf buildmode with pie")
	}
	g.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: config.GoTlsWriteFunc,
				BinaryPath:       g.path,
				UAddress:         g.conf.(*config.GoTLSConfig).GoTlsWriteAddr,
			},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	readOffsets := g.conf.(*config.GoTLSConfig).ReadTlsAddrs
	//g.bpfManager.Probes = []*manager.Probe{}
	g.logger.Info().Str("function", readFn).
		Str("offsets", fmt.Sprintf("%v", readOffsets)).Msg("golang uretprobe added.")
	for _, v := range readOffsets {
		var uid = fmt.Sprintf("%s_%d", readFn, v)
		g.bpfManager.Probes = append(g.bpfManager.Probes, &manager.Probe{
			Section:          readSec,
			EbpfFuncName:     readFn,
			AttachToFuncName: config.GoTlsReadFunc,
			BinaryPath:       g.path,
			UAddress:         uint64(v),
			UID:              uid,
		})
	}
	g.bpfManagerOptions = manager.Options{
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

	if g.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		g.bpfManagerOptions.ConstantEditors = g.constantEditor()
	}
	return nil
}

func (g *GoTLSProbe) initDecodeFunText() error {

	m, found, err := g.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tls_events")
	}

	g.eventMaps = append(g.eventMaps, m)
	gotlsEvent := &event.GoTLSEvent{}
	//sslEvent.SetModule(g)
	g.eventFuncMaps[m] = gotlsEvent
	return nil
}
