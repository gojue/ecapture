package event

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

/*
 u32 pid;
 u8 line[MAX_DATE_SIZE_BASH];
 u32 Retval;
 char Comm[TASK_COMM_LEN];
*/

const MAX_DATA_SIZE_BASH = 256

type BashEvent struct {
	event_type EventType
	Pid        uint32                    `json:"pid"`
	Uid        uint32                    `json:"uid"`
	Line       [MAX_DATA_SIZE_BASH]uint8 `json:"line"`
	Retval     uint32                    `json:"Retval"`
	Comm       [16]byte                  `json:"Comm"`
}

func (this *BashEvent) Decode(payload []byte) (err error) {
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

func (this *BashEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tRetvalue:%d, \tLine:\n%s", this.Pid, this.Uid, this.Comm, this.Retval, unix.ByteSliceToString((this.Line[:]))))
	return s
}

func (this *BashEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tRetvalue:%d, \tLine:\n%s,", this.Pid, this.Uid, this.Comm, this.Retval, dumpByteSlice([]byte(unix.ByteSliceToString((this.Line[:]))), "")))
	return s
}

func (this *BashEvent) Clone() IEventStruct {
	event := new(BashEvent)
	event.event_type = EventTypeOutput
	return event
}

func (this *BashEvent) EventType() EventType {
	return this.event_type
}

func (this *BashEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s", this.Pid, this.Uid, this.Comm)
}

func (this *BashEvent) Payload() []byte {
	return this.Line[:]
}

func (this *BashEvent) PayloadLen() int {
	return len(this.Line)
}
