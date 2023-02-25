// Copyright © 2022 Hengqi Chen
package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type inner struct {
	TimestampNS uint64   `json:"timestamp"`
	Pid         uint32   `json:"pid"`
	Tid         uint32   `json:"tid"`
	Len         int32    `json:"Len"`
	Comm        [16]byte `json:"Comm"`
}

type GoTLSEvent struct {
	inner
	Data []byte `json:"data"`
}

func (e *GoTLSEvent) Decode(payload []byte) error {
	r := bytes.NewBuffer(payload)
	err := binary.Read(r, binary.LittleEndian, &e.inner)
	if e != nil {
		return err
	}
	if e.Len > 0 {
		e.Data = make([]byte, e.Len)
		err = binary.Read(r, binary.LittleEndian, &e.Data)
	}

	return err
}

func (e *GoTLSEvent) String() string {
	s := fmt.Sprintf("PID: %d, Comm: %s, TID: %d, Payload: %s\n", e.Pid, string(e.Comm[:]), e.Tid, string(e.Data[:e.Len]))
	return s
}

func (e *GoTLSEvent) StringHex() string {
	perfix := COLORGREEN
	b := dumpByteSlice(e.Data[:e.Len], perfix)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("PID: %d, Comm: %s, TID: %d, Payload: %s\n", e.Pid, string(e.Comm[:]), e.Tid, b.String())
	return s
}

func (e *GoTLSEvent) Clone() IEventStruct {
	return &GoTLSEvent{}
}

func (e *GoTLSEvent) EventType() EventType {
	return EventTypeOutput
}

func (this *GoTLSEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s", this.Pid, this.Tid, this.Comm)
}

func (this *GoTLSEvent) Payload() []byte {
	return this.Data[:this.Len]
}

func (this *GoTLSEvent) PayloadLen() int {
	return int(this.Len)
}
