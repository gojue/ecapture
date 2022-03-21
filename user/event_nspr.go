/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

type NsprDataEvent struct {
	EventType    int64
	Timestamp_ns uint64
	Pid          uint32
	Tid          uint32
	Data         [MAX_DATA_SIZE]byte
	Data_len     int32
	Comm         [16]byte
}

func (e *NsprDataEvent) Decode(payload []byte) (err error) {
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

func (this *NsprDataEvent) StringHex() string {
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

	var b *bytes.Buffer
	var s string
	// firefox 进程的通讯线程名为 Socket Thread ，过滤 TODO
	var fire_thread string
	fire_thread = strings.TrimSpace(fmt.Sprintf("%s", this.Comm[:13]))
	if strings.Compare(fire_thread, "Socket Thread") != 0 {
		b = bytes.NewBufferString(fmt.Sprintf("%s[ignore]%s", COLORBLUE, COLORRESET))
		s = fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:%s", this.Pid, this.Comm, packetType, this.Tid, this.Data_len, b.String())
	} else {
		b = dumpByteSlice(this.Data[:this.Data_len], perfix)
		b.WriteString(COLORRESET)
		s = fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:\n%s", this.Pid, this.Comm, packetType, this.Tid, this.Data_len, b.String())
	}

	return s
}

func (this *NsprDataEvent) String() string {
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

	var b *bytes.Buffer
	// firefox 进程的通讯线程名为 Socket Thread ，过滤 TODO
	if strings.TrimSpace(string(this.Comm[:13])) != "Socket Thread" {
		b = bytes.NewBufferString("[ignore]")
	} else {
		b = bytes.NewBuffer(this.Data[:this.Data_len])
	}
	s := fmt.Sprintf(" PID:%d, Comm:%s, TID:%d, TYPE:%s, DataLen:%d bytes, Payload:\n%s%s%s", this.Pid, this.Comm, this.Tid, packetType, this.Data_len, perfix, b.String(), COLORRESET)
	return s
}

func (ei *NsprDataEvent) Clone() IEventStruct {
	return new(NsprDataEvent)
}
