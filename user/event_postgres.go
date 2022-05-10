/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

/*
   u64 pid;
   u64 timestamp;
   char query[MAX_DATA_SIZE];
   char comm[TASK_COMM_LEN];
*/
const POSTGRES_MAX_DATA_SIZE = 256

type postgresEvent struct {
	module     IModule
	event_type EVENT_TYPE
	Pid        uint64
	Timestamp  uint64
	query      [POSTGRES_MAX_DATA_SIZE]uint8
	comm       [16]uint8
}

func (this *postgresEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.query); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.comm); err != nil {
		return
	}
	return nil
}

func (this *postgresEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID: %d, Comm: %s, Time: %d, Query: %s", this.Pid, this.comm, this.Timestamp, unix.ByteSliceToString((this.query[:]))))
	return s
}

func (this *postgresEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID: %d, Comm: %s, Time: %d, Query: %s", this.Pid, this.comm, this.Timestamp, unix.ByteSliceToString((this.query[:]))))
	return s
}

func (this *postgresEvent) SetModule(module IModule) {
	this.module = module
}

func (this *postgresEvent) Module() IModule {
	return this.module
}

func (this *postgresEvent) Clone() IEventStruct {
	event := new(postgresEvent)
	event.event_type = EVENT_TYPE_OUTPUT
	return event
}

func (this *postgresEvent) EventType() EVENT_TYPE {
	return this.event_type
}
