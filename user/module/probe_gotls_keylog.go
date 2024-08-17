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
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"golang.org/x/sys/unix"
	"math"
	"strings"
)

func (g *GoTLSProbe) setupManagersKeylog() error {
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
	g.logger.Info().Str("binrayPath", g.path).
		Str("GoVersion", gotlsConf.Buildinfo.GoVersion).
		Str("buildInfo", buildInfo.String()).Msg("HOOK type:Golang elf")
	if gotlsConf.IsPieBuildMode {
		// buildmode pie is enabled.
		g.logger.Warn().Msg("Golang elf buildmode with pie")
	}
	g.logger.Info().Str("Function", config.GoTlsMasterSecretFunc).
		Str("EventCollectorAddr", fmt.Sprintf("%X", gotlsConf.GoTlsMasterSecretAddr)).Msg("Hook masterKey function")
	var (
		sec string
		fn  string
	)

	if g.isRegisterABI {
		sec = "uprobe/gotls_mastersecret_register"
		fn = "gotls_mastersecret_register"
	} else {
		sec = "uprobe/gotls_mastersecret_stack"
		fn = "gotls_mastersecret_stack"
	}

	g.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			// gotls master secrets
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: config.GoTlsMasterSecretFunc,
				BinaryPath:       g.path,
				UID:              "uprobe_gotls_master_secret",
				UAddress:         g.conf.(*config.GoTLSConfig).GoTlsMasterSecretAddr,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "mastersecret_go_events",
			},
		},
	}

	g.bpfManagerOptions = manager.Options{
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

	if g.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		g.bpfManagerOptions.ConstantEditors = g.constantEditor()
	}
	return nil
}

func (g *GoTLSProbe) initDecodeFunKeylog() error {
	// master secrets map at ebpf code
	MasterkeyEventsMap, found, err := g.bpfManager.GetMap("mastersecret_go_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	g.eventMaps = append(g.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	// goTLS Event struct
	masterkeyEvent = &event.MasterSecretGotlsEvent{}

	g.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}
