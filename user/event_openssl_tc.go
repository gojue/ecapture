package user

import (
	"bytes"
	"ecapture/pkg/event_processor"
	"encoding/binary"
)

const (
	SKB_MAX_DATA_SIZE = 2048
)

type TcSkbEvent struct {
	module     IModule
	event_type event_processor.EventType

	DataLen uint32
	Data    [SKB_MAX_DATA_SIZE]byte

	payload string
}

func (this *TcSkbEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Data); err != nil {
		return
	}
	return nil
}

func (this *TcSkbEvent) StringHex() string {
	return "[internal data]"
}

func (this *TcSkbEvent) String() string {
	return "[internal data]"
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
	return "[internal data]"
}

func (this *TcSkbEvent) Payload() []byte {
	return []byte(this.payload)
}

func (this *TcSkbEvent) PayloadLen() int {
	return len(this.payload)
}
