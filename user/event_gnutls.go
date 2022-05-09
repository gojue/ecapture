/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type GnutlsDataEvent struct {
	module       IModule
	event_type   EVENT_TYPE
	DataType     int64
	Timestamp_ns uint64
	Pid          uint32
	Tid          uint32
	Data         [MAX_DATA_SIZE]byte
	Data_len     int32
	Comm         [16]byte
}

func (this *GnutlsDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp_ns); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Data_len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	return nil
}

func (this *GnutlsDataEvent) StringHex() string {
	var perfix, packetType string
	switch AttachType(this.DataType) {
	case PROBE_ENTRY:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case PROBE_RET:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", this.DataType)
	}

	b := dumpByteSlice(this.Data[:this.Data_len], perfix)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:\n%s", this.Pid, this.Comm, packetType, this.Tid, this.Data_len, b.String())
	return s
}

func (this *GnutlsDataEvent) String() string {
	var perfix, packetType string
	switch AttachType(this.DataType) {
	case PROBE_ENTRY:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case PROBE_RET:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = COLORPURPLE
	default:
		packetType = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, this.DataType, COLORRESET)
	}
	s := fmt.Sprintf(" PID:%d, Comm:%s, TID:%d, TYPE:%s, DataLen:%d bytes, Payload:\n%s%s%s", this.Pid, this.Comm, this.Tid, packetType, this.Data_len, perfix, string(this.Data[:this.Data_len]), COLORRESET)
	return s
}

func (this *GnutlsDataEvent) SetModule(module IModule) {
	this.module = module
}

func (this *GnutlsDataEvent) Module() IModule {
	return this.module
}

func (this *GnutlsDataEvent) Clone() IEventStruct {
	event := new(GnutlsDataEvent)
	event.module = this.module
	event.event_type = EVENT_TYPE_OUTPUT
	return event
}

func (this *GnutlsDataEvent) EventType() EVENT_TYPE {
	return this.event_type
}
