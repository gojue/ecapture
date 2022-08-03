package user

import (
	"bytes"
	"ecapture/pkg/event_processor"
	"encoding/binary"
	"fmt"
)

const (
	SKB_MAX_DATA_SIZE = 2048
	TASK_COMM_LEN     = 16
)

type TcSkbEvent struct {
	module     IModule
	event_type event_processor.EventType
	Ts         uint64
	Pid        uint32
	Comm       [TASK_COMM_LEN]byte
	Len        uint32
	Ifindex    uint32
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

func (this *TcSkbEvent) SetModule(module IModule) {
	this.module = module
}

func (this *TcSkbEvent) Module() IModule {
	return this.module
}

func (this *TcSkbEvent) Clone() event_processor.IEventStruct {
	event := new(TcSkbEvent)
	event.module = this.module
	event.event_type = event_processor.EventTypeModuleData
	return event
}

func (this *TcSkbEvent) EventType() event_processor.EventType {
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
