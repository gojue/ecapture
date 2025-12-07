// Copyright © 2022 Hengqi Chen
package event

import (
	"bytes"
	"encoding/binary"
	"fmt"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

type inner struct {
	TimestampNS uint64   `json:"timestamp"`
	Pid         uint32   `json:"pid"`
	Tid         uint32   `json:"tid"`
	Len         int32    `json:"Len"`
	PayloadType uint8    `json:"payloadType"`
	Comm        [16]byte `json:"Comm"`
}

type GoTLSEvent struct {
	inner
	Data []byte `json:"data"`
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
	return Base{
		Timestamp: int64(ge.TimestampNS),
		UUID:      ge.GetUUID(),
		SrcIP:     "127.0.0.1", // GoTLS events do not have SrcIP
		SrcPort:   0,           // GoTLS events do not have SrcPort
		DstIP:     "127.0.0.1", // GoTLS events do not have DstIP
		DstPort:   0,           // GoTLS events do not have DstPort
		PID:       int64(ge.Pid),
		PName:     commStr(ge.Comm[:]),
		Type:      uint32(ge.inner.PayloadType),
		Length:    uint32(ge.Len),
	}
}

func (ge *GoTLSEvent) ToProtobufEvent() *pb.Event {
	return &pb.Event{
		Timestamp: int64(ge.TimestampNS),
		Uuid:      ge.GetUUID(),
		SrcIp:     "127.0.0.1", // GoTLS events do not have SrcIP
		SrcPort:   0,           // GoTLS events do not have SrcPort
		DstIp:     "127.0.0.1", // GoTLS events do not have DstIP
		DstPort:   0,           // GoTLS events do not have DstPort
		Pid:       int64(ge.Pid),
		Pname:     commStr(ge.Comm[:]),
		Type:      uint32(ge.inner.PayloadType),
		Length:    uint32(ge.Len),
		Payload:   ge.Data[:ge.Len],
	}
}

func (ge *GoTLSEvent) Clone() IEventStruct {
	return &GoTLSEvent{}
}

func (ge *GoTLSEvent) EventType() Type {
	return TypeOutput
}

func (ge *GoTLSEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s", ge.Pid, ge.Tid, ge.Comm)
}

func (ge *GoTLSEvent) Payload() []byte {
	return ge.Data[:ge.Len]
}

func (ge *GoTLSEvent) PayloadLen() int {
	return int(ge.Len)
}
