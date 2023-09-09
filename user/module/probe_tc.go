package module

import (
	"bytes"
	"ecapture/pkg/util/ethernet"
	"ecapture/user/event"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"math"
	"net"
	"os"
	"strings"
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

const EcaptureMagic = 0xCC0C4CFC

type packetMetaData struct {
	Magic  uint32 `struc:"uint32"`
	Pid    uint32 `struc:"uint32"`
	CmdLen uint8  `struc:"uint8,sizeof=Cmd"`
	Cmd    string
}

func (p *packetMetaData) Pack() ([]byte, error) {
	buf := new(bytes.Buffer)

	// 使用 binary.BigEndian 将字段按大端字节序写入缓冲区
	err := binary.Write(buf, binary.BigEndian, p.Magic)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, p.Pid)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, p.CmdLen)
	if err != nil {
		return nil, err
	}

	_, err = buf.WriteString(p.Cmd)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
	var payload []byte
	payload = tcEvent.Payload()
	if tcEvent.Pid > 0 {
		err, p := t.writePid(tcEvent)
		if err == nil {
			payload = p
			//fmt.Printf("pid:%d, comm:%s, cmdline:%s\n", tcEvent.Pid, tcEvent.Comm, tcEvent.Cmdline)
		}
	}
	return t.writePacket(uint32(len(payload)), time.Unix(0, int64(timeStamp)), payload)
}

func (t *MTCProbe) writePid(tcEvent *event.TcSkbEvent) (error, []byte) {
	ethPacket := gopacket.NewPacket(
		tcEvent.Payload(),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)

	oldEthLayer := ethPacket.Layers()[0].(*layers.Ethernet)

	// subtract oldethelayer from the begining of ethpacket
	restOfLayers := ethPacket.Layers()[1:]
	remainder := []byte{}
	for _, layer := range restOfLayers {
		// we can correlate metadata only in TCP or UDP for now
		remainder = append(remainder, layer.LayerContents()...)
	}
	metadata := packetMetaData{}
	metadata.Magic = EcaptureMagic
	metadata.Pid = tcEvent.Pid
	var cmd = strings.TrimSpace(fmt.Sprintf("%s", tcEvent.Comm))
	metadata.CmdLen = uint8(len(cmd))
	metadata.Cmd = cmd

	var pt []byte
	var err error
	pt, err = metadata.Pack()
	if err != nil {
		return err, []byte{}
	}
	newEtherLayer := &ethernet.EthernetWithTrailer{
		SrcMAC:       oldEthLayer.SrcMAC,
		DstMAC:       oldEthLayer.DstMAC,
		EthernetType: oldEthLayer.EthernetType,
		Trailer:      pt,
	}

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{false, false}, newEtherLayer, gopacket.Payload(remainder))
	if err != nil {
		return err, []byte{}
	}
	return nil, buffer.Bytes()
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
			Hardware:    "eCapture (旁观者) Hardware",
			OS:          "Linux/Android",
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

		_, err = pcapWriter.AddInterface(ngIface)
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
