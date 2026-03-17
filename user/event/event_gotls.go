// Copyright © 2022 Hengqi Chen
package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// ipToString converts a 4-byte IPv4 or 16-byte IPv6 address to string format
func ipToString(ip []byte) string {
	if len(ip) != 4 && len(ip) != 16 {
		return ""
	}
	return net.IP(ip).String()
}

type inner struct {
	TimestampNS uint64   `json:"timestamp"`
	Pid         uint32   `json:"pid"`
	Tid         uint32   `json:"tid"`
	Len         int32    `json:"Len"`
	PayloadType uint8    `json:"payloadType"`
	Pad         [3]byte  `json:"-"` // Padding for alignment with C struct
	Fd          uint32   `json:"fd"`
	SrcIP       [16]byte `json:"src_ip"`   // Support both IPv4 and IPv6
	SrcPort     uint16   `json:"src_port"`
	Pad2        [2]byte  `json:"-"`         // Padding for alignment
	DstIP       [16]byte `json:"dst_ip"`   // Support both IPv4 and IPv6
	DstPort     uint16   `json:"dst_port"`
	IPVersion   uint8    `json:"ip_version"` // 4 for IPv4, 6 for IPv6
	Pad3        uint8    `json:"-"`          // Padding for alignment
	Comm        [16]byte `json:"Comm"`
}

type GoTLSEvent struct {
	inner
	Data  []byte `json:"data"`
	Tuple string `json:"tuple"`
}

func (ge *GoTLSEvent) Decode(payload []byte) error {
	r := bytes.NewBuffer(payload)
	err := binary.Read(r, binary.LittleEndian, &ge.inner)
	if err != nil {
		return err
	}
	if ge.Len > 0 {
		ge.Data = make([]byte, ge.Len)
		if err = binary.Read(r, binary.LittleEndian, &ge.Data); err != nil {
			return err
		}
	} else {
		ge.Len = 0
	}
	decodedKtime, err := DecodeKtime(int64(ge.TimestampNS), true)
	if err == nil {
		ge.TimestampNS = uint64(decodedKtime.UnixNano())
	}

	return err
}

func (ge *GoTLSEvent) String() string {
	s := fmt.Sprintf("PID: %d, Comm: %s, TID: %d, PayloadType:%d, Payload: %s\n", ge.Pid, string(ge.Comm[:]), ge.Tid, ge.inner.PayloadType, string(ge.Data[:ge.Len]))
	return s
}

func (ge *GoTLSEvent) StringHex() string {
	perfix := COLORGREEN
	b := dumpByteSlice(ge.Data[:ge.Len], perfix)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("PID: %d, Comm: %s, TID: %d, PayloadType:%d, Payload: \n%s\n", ge.Pid, string(ge.Comm[:]), ge.Tid, ge.inner.PayloadType, b.String())
	return s
}

func (ge *GoTLSEvent) Base() Base {
	base := Base{
		Timestamp: int64(ge.TimestampNS),
		UUID:      ge.GetUUID(),
		PID:       int64(ge.Pid),
		PName:     commStr(ge.Comm[:]),
		Type:      uint32(ge.inner.PayloadType),
		Length:    uint32(ge.Len),
	}

	// Use IP and port from eBPF if available.
	// BPF stores: SrcIP/SrcPort = laddr (local), DstIP/DstPort = raddr (remote)
	// PayloadType 0 = WRITE (local→remote): src=local, dst=remote
	// PayloadType 1 = READ  (remote→local): src=remote, dst=local (swap)
	if ge.IPVersion == 4 || ge.IPVersion == 6 {
		var localIP, remoteIP string
		if ge.IPVersion == 4 {
			localIP = ipToString(ge.SrcIP[:4])
			remoteIP = ipToString(ge.DstIP[:4])
		} else {
			localIP = ipToString(ge.SrcIP[:16])
			remoteIP = ipToString(ge.DstIP[:16])
		}
		localPort := uint32(ge.SrcPort)
		remotePort := uint32(ge.DstPort)

		if ge.PayloadType == 0 { // WRITE: local → remote
			base.SrcIP, base.SrcPort = localIP, localPort
			base.DstIP, base.DstPort = remoteIP, remotePort
		} else { // READ: remote → local
			base.SrcIP, base.SrcPort = remoteIP, remotePort
			base.DstIP, base.DstPort = localIP, localPort
		}
	} else {
		// Fallback: parse from Tuple
		ips := strings.Split(ge.Tuple, "-")
		if len(ips) == 2 {
			if srcHost, srcPort, err := net.SplitHostPort(ips[0]); err == nil {
				base.SrcIP = srcHost
				if port, err := strconv.ParseInt(srcPort, 10, 32); err == nil {
					base.SrcPort = uint32(port)
				}
			}
			if dstHost, dstPort, err := net.SplitHostPort(ips[1]); err == nil {
				base.DstIP = dstHost
				if port, err := strconv.ParseInt(dstPort, 10, 32); err == nil {
					base.DstPort = uint32(port)
				}
			}
		}
	}

	return base
}

func (ge *GoTLSEvent) ToProtobufEvent() *pb.Event {
	b := ge.Base()
	return &pb.Event{
		Timestamp: b.Timestamp,
		Uuid:      b.UUID,
		SrcIp:     b.SrcIP,
		SrcPort:   b.SrcPort,
		DstIp:     b.DstIP,
		DstPort:   b.DstPort,
		Pid:       b.PID,
		Pname:     b.PName,
		Type:      b.Type,
		Length:    b.Length,
		Payload:   ge.Payload(),
	}
}

func (ge *GoTLSEvent) Clone() IEventStruct {
	return &GoTLSEvent{}
}

func (ge *GoTLSEvent) EventType() Type {
	return TypeOutput
}

func (ge *GoTLSEvent) GetUUID() string {
	return fmt.Sprintf("gotls:%d_%d_%s_%d_%s", ge.Pid, ge.Tid, commStr(ge.Comm[:]), ge.Fd, ge.Tuple)
}

func (ge *GoTLSEvent) Payload() []byte {
	return ge.Data[:ge.Len]
}

func (ge *GoTLSEvent) PayloadLen() int {
	return int(ge.Len)
}
