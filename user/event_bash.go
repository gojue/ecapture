package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
)

type bashEvent struct {
	module IModule
	Pid    uint32
	Line   [80]uint8
	Comm   [16]byte
}

func (this *bashEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Line); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	return nil
}

func (this *bashEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, \tComm:%s, \tLine:\n%s", this.Pid, this.Comm, unix.ByteSliceToString((this.Line[:]))))
	return s
}

func (this *bashEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, \tComm:%s, \tLine:\n%s", this.Pid, this.Comm, dumpByteSlice([]byte(unix.ByteSliceToString((this.Line[:]))), "")))
	return s
}

func (this *bashEvent) SetModule(module IModule) {
	this.module = module
}

func (this *bashEvent) Module() IModule {
	return this.module
}

func (this *bashEvent) Clone() IEventStruct {
	return new(bashEvent)
}
