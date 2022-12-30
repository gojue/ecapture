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
	manager "github.com/ehids/ebpfmanager"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
	"math"
	"net"
	"os"
	"strings"
	"time"
)

// packets of TC probe
type TcPacket struct {
	info gopacket.CaptureInfo
	data []byte
}

type NetCaptureData struct {
	PacketLength     uint32 `json:"pktLen"`
	ConfigIfaceIndex uint32 `json:"ifIndex"`
}

func (NetCaptureData) GetSizeBytes() uint32 {
	return 8
}

type NetEventMetadata struct {
	TimeStamp   uint64   `json:"timeStamp"`
	HostTid     uint32   `json:"hostTid"`
	ProcessName [16]byte `json:"processName"`
}

func (this *MOpenSSLProbe) setupManagersTC() error {
	var ifname, binaryPath, sslVersion string

	ifname = this.conf.(*config.OpensslConfig).Ifname
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

	sslVersion = this.conf.(*config.OpensslConfig).SslVersion
	sslVersion = strings.ToLower(sslVersion)
	switch this.conf.(*config.OpensslConfig).ElfType {
	case config.ELF_TYPE_BIN:
		binaryPath = this.conf.(*config.OpensslConfig).Curlpath
	case config.ELF_TYPE_SO:
		binaryPath = this.conf.(*config.OpensslConfig).Openssl
		err := this.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libssl.so.1.1"
		err := this.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	}

	this.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", this.Name(), this.conf.(*config.OpensslConfig).ElfType, binaryPath)
	this.logger.Printf("%s\tIfname:%s, Ifindex:%d,  Port:%d, Pcapng filepath:%s\n", this.Name(), this.ifName, this.ifIdex, this.conf.(*config.OpensslConfig).Port, this.pcapngFilename)
	this.logger.Printf("%s\tHook masterKey function:%s\n", this.Name(), this.masterHookFunc)

	// create pcapng writer
	netIfs, err := net.Interfaces()
	if err != nil {
		return err
	}

	err = this.createPcapng(netIfs)
	if err != nil {
		return err
	}

	this.bpfManager = &manager.Manager{
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

			// openssl masterkey
			{
				Section:          "uprobe/SSL_write_key",
				EbpfFuncName:     "probe_ssl_master_key",
				AttachToFuncName: this.masterHookFunc, // SSL_do_handshake or SSL_write
				BinaryPath:       binaryPath,
				UID:              "uprobe_ssl_master_key",
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

func (this *MOpenSSLProbe) initDecodeFunTC() error {
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

	MasterkeyEventsMap, found, err := this.bpfManager.GetMap("mastersecret_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	this.eventMaps = append(this.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	if this.isBoringSSL {
		masterkeyEvent = &event.MasterSecretBSSLEvent{}
	} else {
		masterkeyEvent = &event.MasterSecretEvent{}
	}

	//masterkeyEvent.SetModule(this)
	this.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}

func (this *MOpenSSLProbe) dumpTcSkb(tcEvent *event.TcSkbEvent) {
	var timeStamp = this.bootTime + tcEvent.Ts
	if err := this.writePacket(tcEvent.Len, this.ifIdex, time.Unix(0, int64(timeStamp)), tcEvent.Payload()); err != nil {
		this.logger.Printf("%s\t save packet error %s .\n", this.Name(), err.Error())
	}
	return
}

// save pcapng file ,merge master key into pcapng file TODO
func (this *MOpenSSLProbe) savePcapng() error {
	var i int = 0
	err := this.pcapWriter.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, this.masterKeyBuffer.Bytes())
	if err != nil {
		return err
	}
	this.tcPacketLocker.Lock()
	defer this.tcPacketLocker.Unlock()
	for _, packet := range this.tcPackets {
		err := this.pcapWriter.WritePacket(packet.info, packet.data)
		i++
		if err != nil {
			return err
		}
	}
	this.logger.Printf("%s\t save %d packets into pcapng file.\n", this.Name(), i)
	if i == 0 {
		this.logger.Printf("nothing captured, please check your network interface, see \"ecapture tls -h\" for more information.")
	}
	return this.pcapWriter.Flush()
}

func (this *MOpenSSLProbe) createPcapng(netIfs []net.Interface) error {
	pcapFile, err := os.OpenFile(this.pcapngFilename, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("error creating pcap file: %v", err)
	}

	// TODO : write Application "ecapture.lua" to decode PID/Comm info.
	pcapOption := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    "eCapture Hardware",
			OS:          "",
			Application: "ecapture.lua",
			Comment:     "see https://ecapture.cc for more information. CFC4N <cfc4n.cs@gmail.com>",
		},
	}
	// write interface description
	ngIface := pcapgo.NgInterface{
		Name:       this.conf.(*config.OpensslConfig).Ifname,
		Comment:    "eCapture (旁观者): github.com/gojue/ecapture",
		Filter:     "",
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(math.MaxUint16),
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(pcapFile, ngIface, pcapOption)
	if err != nil {
		return err
	}

	// insert other interfaces into pcapng file
	for _, iface := range netIfs {
		ngIface = pcapgo.NgInterface{
			Name:       iface.Name,
			Comment:    "eCapture (旁观者): github.com/gojue/ecapture",
			Filter:     "",
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		}

		_, err := pcapWriter.AddInterface(ngIface)
		if err != nil {
			return err
		}
	}

	// Flush the header
	err = pcapWriter.Flush()
	if err != nil {
		return err
	}

	// TODO 保存数据包所属进程ID信息，以LRU Cache方式存储。
	this.pcapWriter = pcapWriter
	return nil
}

func (this *MOpenSSLProbe) writePacket(dataLen uint32, ifaceIdx int, timeStamp time.Time, packetBytes []byte) error {
	info := gopacket.CaptureInfo{
		Timestamp:      timeStamp,
		CaptureLength:  int(dataLen),
		Length:         int(dataLen),
		InterfaceIndex: ifaceIdx,
	}

	packet := &TcPacket{info: info, data: packetBytes}

	this.tcPackets = append(this.tcPackets, packet)
	return nil
}

func (this *MOpenSSLProbe) savePcapngSslKeyLog(sslKeyLog []byte) (err error) {
	_, e := this.masterKeyBuffer.Write(sslKeyLog)
	return e
}
