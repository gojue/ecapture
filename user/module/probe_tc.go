package module

import (
	"bytes"
	"ecapture/user/event"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"math"
	"net"
	"os"
	"sync"
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

type MTCProbe struct {
	//logger          *log.Logger
	//mName           string
	pcapngFilename  string
	ifIdex          int
	ifName          string
	pcapWriter      *pcapgo.NgWriter
	startTime       uint64
	bootTime        uint64
	tcPackets       []*TcPacket
	masterKeyBuffer *bytes.Buffer
	tcPacketLocker  *sync.Mutex
}

func (this *MTCProbe) dumpTcSkb(tcEvent *event.TcSkbEvent) error {
	var timeStamp = this.bootTime + tcEvent.Ts
	return this.writePacket(tcEvent.Len, this.ifIdex, time.Unix(0, int64(timeStamp)), tcEvent.Payload())
}

// save pcapng file ,merge master key into pcapng file TODO
func (this *MTCProbe) savePcapng() (i int, err error) {
	err = this.pcapWriter.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, this.masterKeyBuffer.Bytes())
	if err != nil {
		return
	}
	this.tcPacketLocker.Lock()
	defer this.tcPacketLocker.Unlock()
	for _, packet := range this.tcPackets {
		err = this.pcapWriter.WritePacket(packet.info, packet.data)
		i++
		if err != nil {
			return
		}
	}

	if i == 0 {
		return
	}
	err = this.pcapWriter.Flush()
	return
}

func (this *MTCProbe) createPcapng(netIfs []net.Interface) error {
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
		Name:       this.ifName,
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

func (this *MTCProbe) writePacket(dataLen uint32, ifaceIdx int, timeStamp time.Time, packetBytes []byte) error {
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

func (this *MTCProbe) savePcapngSslKeyLog(sslKeyLog []byte) (err error) {
	_, e := this.masterKeyBuffer.Write(sslKeyLog)
	return e
}
