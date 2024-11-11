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

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"golang.org/x/sys/unix"
)

func (m *MGnutlsProbe) setupManagersText() error {
	binaryPath := m.conf.(*config.GnutlsConfig).Gnutls
	m.bpfManager = &manager.Manager{
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

func (m *MGnutlsProbe) initDecodeFunText() error {
	//GnutlsEventsMap 与解码函数映射
	GnutlsEventsMap, found, err := m.bpfManager.GetMap("gnutls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map: gnutls_events")
	}
	m.eventMaps = append(m.eventMaps, GnutlsEventsMap)
	m.eventFuncMaps[GnutlsEventsMap] = &event.GnutlsDataEvent{}
	return nil
}
