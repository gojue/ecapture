//go:build !androidgki
// +build !androidgki

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
u64 pid;
u64 timestamp;
char Query[MAX_DATA_SIZE];
u64 Alllen;
u64 Len;
char Comm[TASK_COMM_LEN];
*/
const MysqldMaxDataSize = 256

const (
	//dispatch_command_return
	DispatchCommandV57Failed       = -2
	DispatchCommandNotCaptured     = -1
	DispatchCommandSuccess         = 0
	DispatchCommandCloseConnection = 1
	DispatchCommandWouldblock      = 2
)

type dispatch_command_return int8

func (d dispatch_command_return) String() string {
	var retStr string
	switch d {
	case DispatchCommandCloseConnection:
		retStr = "DISPATCH_COMMAND_CLOSE_CONNECTION"
	case DispatchCommandSuccess:
		retStr = "DISPATCH_COMMAND_SUCCESS"
	case DispatchCommandWouldblock:
		retStr = "DISPATCH_COMMAND_WOULDBLOCK"
	case DispatchCommandNotCaptured:
		retStr = "DISPATCH_COMMAND_NOT_CAPTURED"
	case DispatchCommandV57Failed:
		retStr = "DISPATCH_COMMAND_V57_FAILED"
	}
	return retStr
}

type MysqldEvent struct {
	eventType EventType
	Pid       uint64                   `json:"pid"`
	Timestamp uint64                   `json:"timestamp"`
	Query     [MysqldMaxDataSize]uint8 `json:"Query"`
	Alllen    uint64                   `json:"Alllen"`
	Len       uint64                   `json:"Len"`
	Comm      [16]uint8                `json:"Comm"`
	Retval    dispatch_command_return  `json:"retval"`
}

func (me *MysqldEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &me.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.Query); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.Alllen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.Len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.Retval); err != nil {
		return
	}
	return nil
}

func (me *MysqldEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  return:%s, Line:%s", me.Pid, me.Comm, me.Timestamp, me.Len, me.Alllen, me.Retval, unix.ByteSliceToString((me.Query[:]))))
	return s
}

func (me *MysqldEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  return:%s, Line:%s", me.Pid, me.Comm, me.Timestamp, me.Len, me.Alllen, me.Retval, unix.ByteSliceToString((me.Query[:]))))
	return s
}

func (me *MysqldEvent) Clone() IEventStruct {
	event := new(MysqldEvent)
	event.eventType = EventTypeOutput
	return event
}

func (me *MysqldEvent) EventType() EventType {
	return me.eventType
}

func (me *MysqldEvent) GetUUID() string {
	return fmt.Sprintf("%d_%s", me.Pid, me.Comm)
}

func (me *MysqldEvent) Payload() []byte {
	return me.Query[:me.Len]
}

func (me *MysqldEvent) PayloadLen() int {
	return int(me.Len)
}
