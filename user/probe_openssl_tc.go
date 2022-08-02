package user

import (
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
	"time"
)

type netPcap struct {
	FileObj os.File
	Writer  pcapgo.NgWriter
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
	var ifname, binaryPath string

	ifname = this.conf.(*OpensslConfig).Ifname
	this.ifName = ifname
	interf, err := net.InterfaceByName(this.conf.(*OpensslConfig).Ifname)
	if err != nil {
		return err
	}
	this.ifIdex = interf.Index

	switch this.conf.(*OpensslConfig).elfType {
	case ELF_TYPE_BIN:
		binaryPath = this.conf.(*OpensslConfig).Curlpath
	case ELF_TYPE_SO:
		binaryPath = this.conf.(*OpensslConfig).Openssl
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libssl.so.1.1"
	}

	this.logger.Printf("%s\tInterface:%s, Pcapng filepath:%s\n", this.Name(), ifname, this.pcapngFilename)

	// create pcapng writer
	err = this.createPcapng()
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
				AttachToFuncName: "SSL_write",
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
	//SSLDumpEventsMap 与解码函数映射
	SkbEventsMap, found, err := this.bpfManager.GetMap("skb_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:skb_events")
	}
	this.eventMaps = append(this.eventMaps, SkbEventsMap)
	sslEvent := &TcSkbEvent{}
	sslEvent.SetModule(this)
	this.eventFuncMaps[SkbEventsMap] = sslEvent

	MasterkeyEventsMap, found, err := this.bpfManager.GetMap("mastersecret_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	this.eventMaps = append(this.eventMaps, MasterkeyEventsMap)
	masterkeyEvent := &MasterSecretEvent{}
	masterkeyEvent.SetModule(this)
	this.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}

func (this *MOpenSSLProbe) dumpTcSkb(event *TcSkbEvent) error {

	this.logger.Printf("%s\t%s, length:%d\n", this.Name(), event.String(), event.DataLen)
	var netEventMetadata *NetEventMetadata = &NetEventMetadata{}
	netEventMetadata.TimeStamp = uint64(time.Now().UnixNano())

	packetBytes := make([]byte, event.DataLen)
	packetBytes = event.Data[:event.DataLen]
	if err := this.writePacket(event.DataLen, this.ifIdex, time.Unix(0, int64(netEventMetadata.TimeStamp)), packetBytes); err != nil {
		return err
	}
	return nil
}

// save pcapng file ,merge master key into pcapng file TODO
func (this *MOpenSSLProbe) savePcapng() error {
	return this.pcapWriter.Flush()
}

func (this *MOpenSSLProbe) createPcapng() error {

	pcapFile, err := os.OpenFile(this.pcapngFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("error creating pcap file: %v", err)
	}

	ngIface := pcapgo.NgInterface{
		Name:       this.conf.(*OpensslConfig).Ifname,
		Comment:    "eCapture TC capture",
		Filter:     "",
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(math.MaxUint16),
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(pcapFile, ngIface, pcapgo.NgWriterOptions{})
	if err != nil {
		return err
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

	// TODO 按照进程PID方式，划分独立的Writer
	err := this.pcapWriter.WritePacket(info, packetBytes)
	if err != nil {
		return err
	}
	return nil
}
