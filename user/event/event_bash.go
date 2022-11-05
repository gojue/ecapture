// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
