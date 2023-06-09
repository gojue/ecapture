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

const MaxDataSizeBash = 256

type BashEvent struct {
	eventType EventType
	Pid       uint32                 `json:"pid"`
	Uid       uint32                 `json:"uid"`
	Line      [MaxDataSizeBash]uint8 `json:"line"`
	Retval    uint32                 `json:"Retval"`
	Comm      [16]byte               `json:"Comm"`
}

func (be *BashEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &be.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Uid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Line); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Retval); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Comm); err != nil {
		return
	}

	return nil
}

func (be *BashEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tRetvalue:%d, \tLine:\n%s", be.Pid, be.Uid, be.Comm, be.Retval, unix.ByteSliceToString((be.Line[:]))))
	return s
}

func (be *BashEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tRetvalue:%d, \tLine:\n%s,", be.Pid, be.Uid, be.Comm, be.Retval, dumpByteSlice([]byte(unix.ByteSliceToString((be.Line[:]))), "")))
	return s
}

func (be *BashEvent) Clone() IEventStruct {
	event := new(BashEvent)
	event.eventType = EventTypeOutput
	return event
}

func (be *BashEvent) EventType() EventType {
	return be.eventType
}

func (be *BashEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s", be.Pid, be.Uid, be.Comm)
}

func (be *BashEvent) Payload() []byte {
	return be.Line[:]
}

func (be *BashEvent) PayloadLen() int {
	return len(be.Line)
}
