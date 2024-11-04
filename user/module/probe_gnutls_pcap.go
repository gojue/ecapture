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
	"fmt"
	"math"
	"net"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"golang.org/x/sys/unix"
)

func (m *MGnutlsProbe) setupManagersPcap() error {
	binaryPath := m.conf.(*config.GnutlsConfig).Gnutls
	ifname := m.conf.(*config.GnutlsConfig).Ifname
	m.ifName = ifname
	interf, err := net.InterfaceByName(m.ifName)
	if err != nil {
		return fmt.Errorf("InterfaceByName: %s , failed: %v", m.ifName, err)
	}

	// loopback devices are special, some tc probes should be skipped
	isNetIfaceLo := interf.Flags&net.FlagLoopback == net.FlagLoopback
	skipLoopback := true // TODO: detect loopback devices via aquasecrity/tracee/pkg/ebpf/probes/probe.go line 322
	if isNetIfaceLo && skipLoopback {
		return fmt.Errorf("%s\t%s is a loopback interface, skip it", m.Name(), m.ifName)
	}
	m.ifIdex = interf.Index

	pcapFilter := m.conf.(*config.GnutlsConfig).PcapFilter
	m.logger.Info().Str("binrayPath", binaryPath).Str("IFname", m.ifName).Int("IFindex", m.ifIdex).
		Str("PcapFilter", pcapFilter).Uint8("ElfType", m.conf.(*config.GnutlsConfig).ElfType).Msg("Hook type: Gnutls elf")
	m.logger.Info().Msg("Hook masterKey function: gnutls_handshake")

	// create pcapng writer
	netIfs, err := net.Interfaces()
	if err != nil {
		return err
	}

	err = m.createPcapng(netIfs)
	if err != nil {
		return err
	}

	// Serve pcapng writer to flush pcapng file
	go func() {
		m.ServePcap()
	}()

	m.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			// customize deleteed TC filter
			// tc filter del dev eth0 ingress
			// tc filter del dev eth0 egress
			// loopback devices are special, some tc probes should be skipped
			// TODO: detect loopback devices via aquasecrity/tracee/pkg/ebpf/probes/probe.go line 322
			// isNetIfaceLo := netIface.Flags&net.FlagLoopback == net.FlagLoopback
			//	if isNetIfaceLo && p.skipLoopback {
			//		return nil
			//	}
			{
				Section:          "classifier/egress",
				EbpfFuncName:     tcFuncNameEgress,
				Ifname:           m.ifName,
				NetworkDirection: manager.Egress,
			},
			{
				Section:          "classifier/ingress",
				EbpfFuncName:     tcFuncNameIngress,
				Ifname:           m.ifName,
				NetworkDirection: manager.Ingress,
			},
			// --------------------------------------------------
			{
				EbpfFuncName:     "tcp_sendmsg",
				Section:          "kprobe/tcp_sendmsg",
				AttachToFuncName: "tcp_sendmsg",
			},
			{
				EbpfFuncName:     "udp_sendmsg",
				Section:          "kprobe/udp_sendmsg",
				AttachToFuncName: "udp_sendmsg",
			},
			// --------------------------------------------------
			{
				Section:          "uprobe/gnutls_handshake",
				EbpfFuncName:     "uprobe_gnutls_master_key",
				AttachToFuncName: "gnutls_handshake",
				BinaryPath:       binaryPath,
				UID:              "uprobe_smk_gnutls_handshake",
			},
			{
				Section:          "uretprobe/gnutls_handshake",
				EbpfFuncName:     "uretprobe_gnutls_master_key",
				AttachToFuncName: "gnutls_handshake",
				BinaryPath:       binaryPath,
				UID:              "uretprobe_smk_gnutls_handshake",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "mastersecret_gnutls_events",
			},
			{
				Name: "skb_events",
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

func (m *MGnutlsProbe) initDecodeFunPcap() error {
	// SkbEventsMap 与解码函数映射
	SkbEventsMap, found, err := m.bpfManager.GetMap("skb_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:skb_events")
	}
	m.eventMaps = append(m.eventMaps, SkbEventsMap)
	sslEvent := &event.TcSkbEvent{}
	// sslEvent.SetModule(m)
	m.eventFuncMaps[SkbEventsMap] = sslEvent

	MasterkeyEventsMap, found, err := m.bpfManager.GetMap("mastersecret_gnutls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map: mastersecret_gnutls_events")
	}
	m.eventMaps = append(m.eventMaps, MasterkeyEventsMap)

	masterkeyEvent := &event.MasterSecretGnutlsEvent{}
	// masterkeyEvent.SetModule(m)
	m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}
