// Author: yuweizzz <yuwei764969238@gmail.com>.
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
	"math"
	"os"
	"path"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"golang.org/x/sys/unix"
)

func (g *MGnutlsProbe) setupManagersKeylog() error {
	var binaryPath string
	switch g.conf.(*config.GnutlsConfig).ElfType {
	case config.ElfTypeSo:
		binaryPath = g.conf.(*config.GnutlsConfig).Gnutls
	default:
		//如果没找到  "/lib/x86_64-linux-gnu/libgnutls.so.30"
		binaryPath = path.Join(defaultSoPath, "libgnutls.so.30")
	}
	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	g.logger.Info().Str("binaryPath", binaryPath).Uint8("elfType", g.conf.(*config.GnutlsConfig).ElfType).Msg("gnutls binary path")
	g.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/gnutls_handshake",
				EbpfFuncName:     "uprobe_gnutls_master_key",
				AttachToFuncName: "gnutls_handshake",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/gnutls_handshake",
				EbpfFuncName:     "uretprobe_gnutls_master_key",
				AttachToFuncName: "gnutls_handshake",
				BinaryPath:       binaryPath,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "mastersecret_gnutls_events",
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

func (m *MGnutlsProbe) initDecodeFunKeylog() error {
	MasterkeyEventsMap, found, err := m.bpfManager.GetMap("mastersecret_gnutls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map: mastersecret_gnutls_events")
	}
	m.eventMaps = append(m.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	masterkeyEvent = &event.MasterSecretGnutlsEvent{}

	m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}
