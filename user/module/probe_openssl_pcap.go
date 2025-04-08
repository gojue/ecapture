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
	"net"
	"path"
	"strings"

	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type NetEventMetadata struct {
	TimeStamp   uint64   `json:"timeStamp"`
	HostTid     uint32   `json:"hostTid"`
	ProcessName [16]byte `json:"processName"`
}

func (m *MOpenSSLProbe) setupManagersPcap() error {
	var ifname, binaryPath, sslVersion string

	ifname = m.conf.(*config.OpensslConfig).Ifname
	m.ifName = ifname
	interf, err := net.InterfaceByName(m.ifName)
	if err != nil {
		return fmt.Errorf("InterfaceByName: %s , failed: %v", m.ifName, err)
	}

	m.ifIdex = interf.Index

	sslVersion = m.conf.(*config.OpensslConfig).SslVersion
	sslVersion = strings.ToLower(sslVersion)
	switch m.conf.(*config.OpensslConfig).ElfType {
	// case config.ElfTypeBin:
	//	binaryPath = m.conf.(*config.OpensslConfig).Curlpath
	case config.ElfTypeSo:
		binaryPath = m.conf.(*config.OpensslConfig).Openssl
		err = m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	default:
		// 如果没找到
		binaryPath = path.Join(defaultSoPath, "libssl.so.1.1")
		err = m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	}

	pcapFilter := m.conf.(*config.OpensslConfig).PcapFilter
	m.logger.Info().Str("binrayPath", binaryPath).Str("IFname", m.ifName).Int("IFindex", m.ifIdex).
		Str("PcapFilter", pcapFilter).Uint8("ElfType", m.conf.(*config.OpensslConfig).ElfType).Msg("HOOK type:Openssl elf")
	m.logger.Info().Strs("Functions", m.masterHookFuncs).Msg("Hook masterKey function")

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
		},

		Maps: []*manager.Map{
			{
				Name: "mastersecret_events",
			},
			{
				Name: "skb_events",
			},
		},
	}

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

func (m *MOpenSSLProbe) initDecodeFunPcap() error {
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

	// masterkeyEvent.SetModule(m)
	m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}
