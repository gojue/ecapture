package module

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"ecapture/pkg/util/ethernet"
	"ecapture/user/event"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jschwinger233/elibpcap"
)

var eOverflow = errors.New("pcapNG channel overflow")

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
	Module
	pcapngFilename  string
	ifIdex          int
	ifName          string
	pcapWriter      *pcapgo.NgWriter
	startTime       uint64
	bootTime        uint64
	tcPackets       []*TcPacket
	masterKeyBuffer *bytes.Buffer
	tcPacketLocker  *sync.Mutex
	tcPacketsChan   chan *TcPacket
}

func (t *MTCProbe) dumpTcSkb(tcEvent *event.TcSkbEvent) error {
	timeStamp := t.bootTime + tcEvent.Ts
	var payload []byte
	payload = tcEvent.Payload()
	if tcEvent.Pid > 0 {
		err, p := t.writePid(tcEvent)
		if err == nil {
			payload = p
			// fmt.Printf("pid:%d, comm:%s, cmdline:%s\n", tcEvent.Pid, tcEvent.Comm, tcEvent.Cmdline)
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
	cmd := strings.TrimSpace(fmt.Sprintf("%s", tcEvent.Comm))
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
	defer func() {
		t.tcPacketLocker.Unlock()
	}()
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
	pcapFile, err := os.OpenFile(t.pcapngFilename, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0o644)
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

	select {
	case t.tcPacketsChan <- packet:
		return nil
	default:
		return eOverflow
	}
}

func (t *MTCProbe) savePcapngSslKeyLog(sslKeyLog []byte) (err error) {
	_, e := t.masterKeyBuffer.Write(sslKeyLog)
	return e
}

// ServePcap is used to serve pcapng file
func (t *MTCProbe) ServePcap() {
	ti := time.NewTicker(2 * time.Second)
	t.logger.Printf("%s\tsaving pcapng file: %s\n", t.Name(), t.pcapngFilename)
	var allCount int
	defer func() {
		if allCount == 0 {
			t.logger.Printf("%s\tnothing captured, please check your network interface, see \"ecapture tls -h\" for more information.", t.Name())
		} else {
			t.logger.Printf("%s\t save %d packets into pcapng file.\n", t.Name(), allCount)
		}
		ti.Stop()
	}()

	var i int
	for {
		select {
		case _ = <-ti.C:
			if i == 0 || len(t.tcPackets) == 0 {
				continue
			}
			n, e := t.savePcapng()
			if e != nil {
				t.logger.Printf("%s\tsave pcapng err:%s, maybe %d packets lost.\n", t.Name(), e.Error(), i)
			} else {
				t.logger.Printf("%s\tsave pcapng success, count:%d\n", t.Name(), n)
				allCount += n
			}

			// reset counter, and reset tcPackets array
			i = 0
			t.tcPackets = t.tcPackets[:0]
		case packet, ok := <-t.tcPacketsChan:
			// append tcPackets to tcPackets Array from tcPacketsChan
			if !ok {
				t.logger.Printf("%s\ttcPacketsChan closed.\n", t.Name())
			}
			t.tcPackets = append(t.tcPackets, packet)
			i++
		case _ = <-t.ctx.Done():
			if i == 0 || len(t.tcPackets) == 0 {
				return
			}
			n, e := t.savePcapng()
			if e != nil {
				t.logger.Printf("%s\tsave pcapng err:%s, maybe %d packets lost.\n", t.Name(), e.Error(), i)
			} else {
				t.logger.Printf("%s\tsave pcapng success, count:%d\n", t.Name(), n)
				allCount += n
			}
			return
		}
	}
}

func injectPcapFilter(progSpec *ebpf.ProgramSpec, pcapFilter string) (*ebpf.ProgramSpec, error) {
	if pcapFilter == "" {
		return progSpec, nil
	}

	var err error
	progSpec.Instructions, err = elibpcap.Inject(pcapFilter, progSpec.Instructions, elibpcap.Options{
		AtBpf2Bpf:  "filter_pcap_ebpf_l2",
		DirectRead: true,
		L2Skb:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to inject pcap filter: %w", err)
	}

	return progSpec, nil
}

func prepareInsnPatchers(m *manager.Manager, ebpfFuncs []string, pcapFilter string) []manager.InstructionPatcherFunc {
	preparePatcher := func(ebpfFunc string) manager.InstructionPatcherFunc {
		return func(m *manager.Manager) error {
			progSpecs, ok, err := m.GetProgramSpec(manager.ProbeIdentificationPair{EbpfFuncName: ebpfFunc})
			if err != nil || !ok || len(progSpecs) == 0 {
				return fmt.Errorf("failed to get program spec for %s: %w", ebpfFunc, err)
			}

			for _, progSpec := range progSpecs {
				_, err = injectPcapFilter(progSpec, pcapFilter)
				if err != nil {
					return fmt.Errorf("failed to inject pcap filter for %s: %w", ebpfFunc, err)
				}
			}

			return nil
		}
	}

	insnPatchers := make([]manager.InstructionPatcherFunc, 0, len(ebpfFuncs))
	for _, ebpfFunc := range ebpfFuncs {
		fn := ebpfFunc
		insnPatchers = append(insnPatchers, preparePatcher(fn))
	}

	return insnPatchers
}
