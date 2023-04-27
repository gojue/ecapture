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
	EventType   uint8    `json:"eventType"`
	Comm        [16]byte `json:"Comm"`
}

type GoTLSEvent struct {
	inner
	Data []byte `json:"data"`
}

func (this *GoTLSEvent) Decode(payload []byte) error {
	r := bytes.NewBuffer(payload)
	err := binary.Read(r, binary.LittleEndian, &this.inner)
	if err != nil {
		return err
	}
	if this.Len > 0 {
		this.Data = make([]byte, this.Len)
		err = binary.Read(r, binary.LittleEndian, &this.Data)
	}

	return err
}

func (this *GoTLSEvent) String() string {
	s := fmt.Sprintf("PID: %d, Comm: %s, TID: %d, Payload: %s\n", this.Pid, string(this.Comm[:]), this.Tid, string(this.Data[:this.Len]))
	return s
}

func (this *GoTLSEvent) StringHex() string {
	perfix := COLORGREEN
	b := dumpByteSlice(this.Data[:this.Len], perfix)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("PID: %d, Comm: %s, TID: %d, Payload: %s\n", this.Pid, string(this.Comm[:]), this.Tid, b.String())
	return s
}

func (this *GoTLSEvent) Clone() IEventStruct {
	return &GoTLSEvent{}
}

func (this *GoTLSEvent) EventType() EventType {
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
