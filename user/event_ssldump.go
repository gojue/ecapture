/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type AttachType int64

const (
	PROBE_ENTRY AttachType = iota
	PROBE_RET
)

const MAX_DATA_SIZE = 1024 * 4

type SSLDataEvent struct {
	EventType    int64
	Timestamp_ns uint64
	Pid          uint32
	Tid          uint32
	Data         [MAX_DATA_SIZE]byte
	Data_len     int32
	Comm         [16]byte
}

func (e *SSLDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &e.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Timestamp_ns); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Data_len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return
	}
	return nil
}

func (this *SSLDataEvent) StringHex() string {
	var perfix, packetType string
	switch AttachType(this.EventType) {
	case PROBE_ENTRY:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case PROBE_RET:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", this.EventType)
	}

	b := dumpByteSlice(this.Data[:this.Data_len], perfix)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d, Payload:\n%s", this.Pid, this.Comm, packetType, this.Tid, this.Data_len, b.String())
	return s
}

func (this *SSLDataEvent) String() string {
	var perfix, packetType string
	switch AttachType(this.EventType) {
	case PROBE_ENTRY:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case PROBE_RET:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = COLORPURPLE
	default:
		packetType = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, this.EventType, COLORRESET)
	}
	s := fmt.Sprintf(" PID:%d, Comm:%s, TID:%d, TYPE:%s, DataLen:%d, Payload:\n%s%s%s", this.Pid, this.Comm, this.Tid, packetType, this.Data_len, perfix, string(this.Data[:this.Data_len]), COLORRESET)
	return s
}

func (ei *SSLDataEvent) Clone() IEventStruct {
	return new(SSLDataEvent)
}
