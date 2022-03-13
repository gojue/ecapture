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

type SSLDataEvent struct {
	EventType    int64
	Timestamp_ns uint64
	Pid          uint32
	Tid          uint32
	Data         [4096]byte
	Data_len     int32
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
	return nil
}

func (ei *SSLDataEvent) String() string {
	var af string
	switch AttachType(ei.EventType) {
	case PROBE_ENTRY:
		af = "PROBE_ENTRY"
	case PROBE_RET:
		af = "PROBE_RET"
	default:
		af = fmt.Sprintf("UNKNOW_%d", ei.EventType)
	}
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, TID:%d, TYPE:%s, DataLen:%d, Data:%s", ei.Pid, ei.Tid, af, ei.Data_len, string(ei.Data[:ei.Data_len])))
	return s
}

func (ei *SSLDataEvent) Clone() IEventStruct {
	return new(SSLDataEvent)
}
