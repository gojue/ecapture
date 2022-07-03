package user

import (
	"bytes"
	"ecapture/pkg/event_processor"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

/*
 u32 pid;
 u8 line[MAX_DATE_SIZE_BASH];
 u32 retval;
 char comm[TASK_COMM_LEN];
*/

const MAX_DATA_SIZE_BASH = 256

type bashEvent struct {
	module     IModule
	event_type event_processor.EVENT_TYPE
	Pid        uint32
	Uid        uint32
	Line       [MAX_DATA_SIZE_BASH]uint8
	Retval     uint32
	Comm       [16]byte
}

func (this *bashEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Uid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Line); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Retval); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}

	return nil
}

func (this *bashEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tRetvalue:%d, \tLine:\n%s", this.Pid, this.Uid, this.Comm, this.Retval, unix.ByteSliceToString((this.Line[:]))))
	return s
}

func (this *bashEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tRetvalue:%d, \tLine:\n%s,", this.Pid, this.Uid, this.Comm, this.Retval, dumpByteSlice([]byte(unix.ByteSliceToString((this.Line[:]))), "")))
	return s
}

func (this *bashEvent) SetModule(module IModule) {
	this.module = module
}

func (this *bashEvent) Module() IModule {
	return this.module
}

func (this *bashEvent) Clone() event_processor.IEventStruct {
	event := new(bashEvent)
	event.module = this.module
	event.event_type = event_processor.EVENT_TYPE_OUTPUT
	return event
}

func (this *bashEvent) EventType() event_processor.EVENT_TYPE {
	return this.event_type
}

func (this *bashEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s", this.Pid, this.Uid, this.Comm)
}

func (this *bashEvent) Payload() []byte {
	return this.Line[:]
}

func (this *bashEvent) PayloadLen() int {
	return len(this.Line)
}
