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
	"path"
	"strings"
)

func (m *MOpenSSLProbe) setupManagersKeylog() error {
	var binaryPath, sslVersion string

	sslVersion = m.conf.(*config.OpensslConfig).SslVersion
	sslVersion = strings.ToLower(sslVersion)
	switch m.conf.(*config.OpensslConfig).ElfType {
	//case config.ElfTypeBin:
	//	binaryPath = m.conf.(*config.OpensslConfig).Curlpath
	case config.ElfTypeSo:
		binaryPath = m.conf.(*config.OpensslConfig).Openssl
		err := m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	default:
		//如果没找到
		binaryPath = path.Join(defaultSoPath, "libssl.so.1.1")
		err := m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	}

	m.logger.Info().Str("binrayPath", binaryPath).Uint8("ElfType", m.conf.(*config.OpensslConfig).ElfType).
		Strs("masterHookFuncs", m.masterHookFuncs).Msg("HOOK type:Openssl elf")
	m.bpfManager = &manager.Manager{
		Maps: []*manager.Map{
			{
				Name: "mastersecret_events",
			},
		},
	}
	m.bpfManager.Probes = make([]*manager.Probe, 0)
	for _, masterFunc := range m.masterHookFuncs {
		m.bpfManager.Probes = append(m.bpfManager.Probes, &manager.Probe{
			Section:          "uprobe/SSL_write_key",
			EbpfFuncName:     "probe_ssl_master_key",
			AttachToFuncName: masterFunc,
			BinaryPath:       binaryPath,
			UID:              fmt.Sprintf("uprobe_smk_%s", masterFunc),
		})
	}

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

	if m.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		m.bpfManagerOptions.ConstantEditors = m.constantEditor()
	}
	return nil
}

func (m *MOpenSSLProbe) initDecodeFunKeylog() error {
	MasterkeyEventsMap, found, err := m.bpfManager.GetMap("mastersecret_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	m.eventMaps = append(m.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	if m.isBoringSSL {
		masterkeyEvent = &event.MasterSecretBSSLEvent{}
	} else {
		masterkeyEvent = &event.MasterSecretEvent{}
	}

	//masterkeyEvent.SetModule(m)
	m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}
