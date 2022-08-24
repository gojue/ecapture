/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

type NsprDataEvent struct {
	event_type EventType
	DataType   int64               `json:"dataType"`
	Timestamp  uint64              `json:"timestamp"`
	Pid        uint32              `json:"pid"`
	Tid        uint32              `json:"tid"`
	Data       [MAX_DATA_SIZE]byte `json:"data"`
	DataLen    int32               `json:"dataLen"`
	Comm       [16]byte            `json:"Comm"`
}

func (this *NsprDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp); err != nil {
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
	if err = binary.Read(buf, binary.LittleEndian, &this.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	return nil
}

func (this *NsprDataEvent) StringHex() string {
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

	var b *bytes.Buffer
	var s string
	// firefox 进程的通讯线程名为 Socket Thread
	var fire_thread = strings.TrimSpace(fmt.Sprintf("%s", this.Comm[:13]))
	// disable filter default
	if false && strings.Compare(fire_thread, "Socket Thread") != 0 {
		b = bytes.NewBufferString(fmt.Sprintf("%s[ignore]%s", COLORBLUE, COLORRESET))
		s = fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:%s", this.Pid, this.Comm, packetType, this.Tid, this.DataLen, b.String())
	} else {
		b = dumpByteSlice(this.Data[:this.DataLen], perfix)
		b.WriteString(COLORRESET)
		s = fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:\n%s", this.Pid, this.Comm, packetType, this.Tid, this.DataLen, b.String())
	}

	return s
}

func (this *NsprDataEvent) String() string {
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

	var b *bytes.Buffer
	// firefox 进程的通讯线程名为 Socket Thread
	// disable filter default
	if false && strings.TrimSpace(string(this.Comm[:13])) != "Socket Thread" {
		b = bytes.NewBufferString("[ignore]")
	} else {
		b = bytes.NewBuffer(this.Data[:this.DataLen])
	}
	s := fmt.Sprintf(" PID:%d, Comm:%s, TID:%d, TYPE:%s, DataLen:%d bytes, Payload:\n%s%s%s", this.Pid, this.Comm, this.Tid, packetType, this.DataLen, perfix, b.String(), COLORRESET)
	return s
}

func (this *NsprDataEvent) Clone() IEventStruct {
	event := new(NsprDataEvent)
	event.event_type = EventTypeEventProcessor
	return event
}

func (this *NsprDataEvent) EventType() EventType {
	return this.event_type
}

func (this *NsprDataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d", this.Pid, this.Tid, this.Comm, this.DataType)
}

func (this *NsprDataEvent) Payload() []byte {
	return this.Data[:this.DataLen]
}

func (this *NsprDataEvent) PayloadLen() int {
	return int(this.DataLen)
}
