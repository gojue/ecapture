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

	"ecapture/user/config"
	"ecapture/user/event"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

const (
	tcFuncNameIngress = "ingress_cls_func"
	tcFuncNameEgress  = "egress_cls_func"
)

func (g *GoTLSProbe) setupManagersPcap() error {
	var ifname string

	ifname = g.conf.(*config.GoTLSConfig).Ifname
	g.ifName = ifname
	interf, err := net.InterfaceByName(g.ifName)
	if err != nil {
		return err
	}

	// loopback devices are special, some tc probes should be skipped
	isNetIfaceLo := interf.Flags&net.FlagLoopback == net.FlagLoopback
	skipLoopback := true // TODO: detect loopback devices via aquasecrity/tracee/pkg/ebpf/probes/probe.go line 322
	if isNetIfaceLo && skipLoopback {
		return fmt.Errorf("%s\t%s is a loopback interface, skip it", g.Name(), g.ifName)
	}
	g.ifIdex = interf.Index

	pcapFilter := g.conf.(*config.GoTLSConfig).PcapFilter
	g.logger.Printf("%s\tHOOK type:golang elf, binrayPath:%s\n", g.Name(), g.path)
	g.logger.Printf("%s\tPcapFilter: %s\n", g.Name(), pcapFilter)
	g.logger.Printf("%s\tIfname: %s, Ifindex: %d\n", g.Name(), g.ifName, g.ifIdex)
	g.logger.Printf("%s\tHook masterKey function: %s, Address:%x \n", g.Name(), config.GoTlsMasterSecretFunc, g.conf.(*config.GoTLSConfig).GoTlsMasterSecretAddr)

	// create pcapng writer
	netIfs, err := net.Interfaces()
	if err != nil {
		return err
	}

	err = g.createPcapng(netIfs)
	if err != nil {
		return err
	}

	// Serve pcapng writer to flush pcapng file
	go func() {
		g.ServePcap()
	}()

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
			{
				Section:          "classifier/egress",
				EbpfFuncName:     tcFuncNameEgress,
				Ifname:           g.ifName,
				NetworkDirection: manager.Egress,
			},
			{
				Section:          "classifier/ingress",
				EbpfFuncName:     tcFuncNameIngress,
				Ifname:           g.ifName,
				NetworkDirection: manager.Ingress,
			},
			// --------------------------------------------------

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
			{
				Name: "skb_events",
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

func (g *GoTLSProbe) initDecodeFunPcap() error {
	// SkbEventsMap 与解码函数映射
	SkbEventsMap, found, err := g.bpfManager.GetMap("skb_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:skb_events")
	}
	g.eventMaps = append(g.eventMaps, SkbEventsMap)
	sslEvent := &event.TcSkbEvent{}
	// sslEvent.SetModule(g)
	g.eventFuncMaps[SkbEventsMap] = sslEvent

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
