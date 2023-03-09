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
	"ecapture/user/config"
	"ecapture/user/event"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
	"math"
	"net"
)

func (this *GoTLSProbe) setupManagersTC() error {
	var ifname string

	ifname = this.conf.(*config.GoTLSConfig).Ifname
	this.ifName = ifname
	interf, err := net.InterfaceByName(this.ifName)
	if err != nil {
		return err
	}

	// loopback devices are special, some tc probes should be skipped
	isNetIfaceLo := interf.Flags&net.FlagLoopback == net.FlagLoopback
	skipLoopback := true // TODO: detect loopback devices via aquasecrity/tracee/pkg/ebpf/probes/probe.go line 322
	if isNetIfaceLo && skipLoopback {
		return fmt.Errorf("%s\t%s is a loopback interface, skip it", this.Name(), this.ifName)
	}
	this.ifIdex = interf.Index

	this.logger.Printf("%s\tHOOK type:golang elf, binrayPath:%s\n", this.Name(), this.path)
	this.logger.Printf("%s\tIfname:%s, Ifindex:%d,  Port:%d, Pcapng filepath:%s\n", this.Name(), this.ifName, this.ifIdex, this.conf.(*config.GoTLSConfig).Port, this.pcapngFilename)
	this.logger.Printf("%s\tHook masterKey function:%s\n", this.Name(), goTlsMasterSecretFunc)

	// create pcapng writer
	netIfs, err := net.Interfaces()
	if err != nil {
		return err
	}

	err = this.createPcapng(netIfs)
	if err != nil {
		return err
	}

	var (
		sec string
		fn  string
	)

	if this.isRegisterABI {
		sec = "uprobe/gotls_mastersecret_register"
		fn = "gotls_mastersecret_register"
	} else {
		sec = "uprobe/gotls_mastersecret_stack"
		fn = "gotls_mastersecret_stack"
	}

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "classifier/egress",
				EbpfFuncName:     "egress_cls_func",
				Ifname:           this.ifName,
				NetworkDirection: manager.Egress,
			},
			{
				Section:          "classifier/ingress",
				EbpfFuncName:     "ingress_cls_func",
				Ifname:           this.ifName,
				NetworkDirection: manager.Ingress,
			},
			// --------------------------------------------------

			// gotls master secrets
			{
				Section:          sec,
				EbpfFuncName:     fn,
				AttachToFuncName: goTlsMasterSecretFunc,
				BinaryPath:       this.path,
				UID:              "uprobe_gotls_master_secret",
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

	this.bpfManagerOptions = manager.Options{
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

	if this.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		this.bpfManagerOptions.ConstantEditors = this.constantEditor()
	}
	return nil
}

func (this *GoTLSProbe) initDecodeFunTC() error {
	//SkbEventsMap 与解码函数映射
	SkbEventsMap, found, err := this.bpfManager.GetMap("skb_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:skb_events")
	}
	this.eventMaps = append(this.eventMaps, SkbEventsMap)
	sslEvent := &event.TcSkbEvent{}
	//sslEvent.SetModule(this)
	this.eventFuncMaps[SkbEventsMap] = sslEvent

	// master secrets map at ebpf code
	MasterkeyEventsMap, found, err := this.bpfManager.GetMap("mastersecret_go_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	this.eventMaps = append(this.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	// goTLS Event struct
	masterkeyEvent = &event.MasterSecretGotlsEvent{}

	this.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}

func (this *GoTLSProbe) Events() []*ebpf.Map {
	return this.eventMaps
}
