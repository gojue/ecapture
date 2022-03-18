package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
)

type bashEvent struct {
	Pid  uint32
	Line [80]uint8
	Comm [16]byte
}

func (e *bashEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Line); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return
	}
	return nil
}

func (ei *bashEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, \tComm:%s, \tLine:%s", ei.Pid, ei.Comm, unix.ByteSliceToString((ei.Line[:]))))
	return s
}

func (ei *bashEvent) Clone() IEventStruct {
	return new(bashEvent)
}
