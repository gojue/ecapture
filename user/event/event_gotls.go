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

type inner struct {
	TimestampNS uint64   `json:"timestamp"`
	Pid         uint32   `json:"pid"`
	Tid         uint32   `json:"tid"`
	Len         int32    `json:"Len"`
	PayloadType uint8    `json:"payloadType"`
	Pad         [3]byte  `json:"-"` // Padding for alignment with C struct
	Fd          uint32   `json:"fd"`
	Comm        [16]byte `json:"Comm"`
}

type GoTLSEvent struct {
	inner
	Data  []byte `json:"data"`
	Tuple string `json:"tuple"`
	Sock  uint64 `json:"sock"`
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
	return fmt.Sprintf("gotls:%d_%d_%s_%d_%s_%d", ge.Pid, ge.Tid, commStr(ge.Comm[:]), ge.Fd, ge.Tuple, ge.Sock)
}

func (ge *GoTLSEvent) Payload() []byte {
	return ge.Data[:ge.Len]
}

func (ge *GoTLSEvent) PayloadLen() int {
	return int(ge.Len)
}
