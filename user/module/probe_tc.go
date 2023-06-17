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

func (t *MTCProbe) dumpTcSkb(tcEvent *event.TcSkbEvent) error {
	var timeStamp = t.bootTime + tcEvent.Ts
	return t.writePacket(tcEvent.Len, time.Unix(0, int64(timeStamp)), tcEvent.Payload())
}

// save pcapng file ,merge master key into pcapng file TODO
func (t *MTCProbe) savePcapng() (i int, err error) {
	err = t.pcapWriter.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, t.masterKeyBuffer.Bytes())
	if err != nil {
		return
	}
	t.tcPacketLocker.Lock()
	defer t.tcPacketLocker.Unlock()
	for _, packet := range t.tcPackets {
		err = t.pcapWriter.WritePacket(packet.info, packet.data)
		i++
		if err != nil {
			return
		}
	}

	if i == 0 {
		return
	}
	err = t.pcapWriter.Flush()
	return
}

func (t *MTCProbe) createPcapng(netIfs []net.Interface) error {
	pcapFile, err := os.OpenFile(t.pcapngFilename, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0644)
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
		Name:       t.ifName,
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
	t.pcapWriter = pcapWriter
	return nil
}

func (t *MTCProbe) writePacket(dataLen uint32, timeStamp time.Time, packetBytes []byte) error {

	// TODO add packetMeta info (e.g: process. pid, commom, etc.)
	
	info := gopacket.CaptureInfo{
		Timestamp:     timeStamp,
		CaptureLength: int(dataLen),
		Length:        int(dataLen),

		// set 0 default, Because the monitored network interface is the first one written into the pcapng header.
		// 设置为0，因为被监听的网卡是第一个写入pcapng header中的。
		// via : https://github.com/gojue/ecapture/issues/347
		InterfaceIndex: 0,
	}

	packet := &TcPacket{info: info, data: packetBytes}

	t.tcPackets = append(t.tcPackets, packet)
	return nil
}

func (t *MTCProbe) savePcapngSslKeyLog(sslKeyLog []byte) (err error) {
	_, e := t.masterKeyBuffer.Write(sslKeyLog)
	return e
}
