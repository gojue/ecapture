package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	SKB_MAX_DATA_SIZE = 2048
	TASK_COMM_LEN     = 16
)

type TcSkbEvent struct {
	event_type EventType
	Ts         uint64              `json:"ts"`
	Pid        uint32              `json:"pid"`
	Comm       [TASK_COMM_LEN]byte `json:"Comm"`
	Len        uint32              `json:"len"`
	Ifindex    uint32              `json:"ifindex"`
	payload    []byte
}

func (this *TcSkbEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Ts); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Ifindex); err != nil {
		return
	}
	tmpData := make([]byte, this.Len)
	if err = binary.Read(buf, binary.LittleEndian, &tmpData); err != nil {
		return
	}
	this.payload = tmpData
	return nil
}

func (this *TcSkbEvent) StringHex() string {
	b := dumpByteSlice(this.payload, COLORGREEN)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:%s", this.Pid, this.Comm, this.Len, this.Ifindex, b.String())
	return s
}

func (this *TcSkbEvent) String() string {

	s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:[internal data]", this.Pid, this.Comm, this.Len, this.Ifindex)
	return s
}

func (this *TcSkbEvent) Clone() IEventStruct {
	event := new(TcSkbEvent)
	event.event_type = EventTypeModuleData
	return event
}

func (this *TcSkbEvent) EventType() EventType {
	return this.event_type
}

func (this *TcSkbEvent) GetUUID() string {
	return fmt.Sprintf("%d-%d-%s", this.Pid, this.Ifindex, this.Comm)
}

func (this *TcSkbEvent) Payload() []byte {
	return this.payload
}

func (this *TcSkbEvent) PayloadLen() int {
	return int(this.Len)
}
