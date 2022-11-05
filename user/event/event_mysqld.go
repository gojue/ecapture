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
const MYSQLD_MAX_DATA_SIZE = 256

const (
	//dispatch_command_return
	DISPATCH_COMMAND_V57_FAILED       = -2
	DISPATCH_COMMAND_NOT_CAPTURED     = -1
	DISPATCH_COMMAND_SUCCESS          = 0
	DISPATCH_COMMAND_CLOSE_CONNECTION = 1
	DISPATCH_COMMAND_WOULDBLOCK       = 2
)

type dispatch_command_return int8

func (this dispatch_command_return) String() string {
	var retStr string
	switch this {
	case DISPATCH_COMMAND_CLOSE_CONNECTION:
		retStr = "DISPATCH_COMMAND_CLOSE_CONNECTION"
	case DISPATCH_COMMAND_SUCCESS:
		retStr = "DISPATCH_COMMAND_SUCCESS"
	case DISPATCH_COMMAND_WOULDBLOCK:
		retStr = "DISPATCH_COMMAND_WOULDBLOCK"
	case DISPATCH_COMMAND_NOT_CAPTURED:
		retStr = "DISPATCH_COMMAND_NOT_CAPTURED"
	case DISPATCH_COMMAND_V57_FAILED:
		retStr = "DISPATCH_COMMAND_V57_FAILED"
	}
	return retStr
}

type MysqldEvent struct {
	event_type EventType
	Pid        uint64                      `json:"pid"`
	Timestamp  uint64                      `json:"timestamp"`
	Query      [MYSQLD_MAX_DATA_SIZE]uint8 `json:"Query"`
	Alllen     uint64                      `json:"Alllen"`
	Len        uint64                      `json:"Len"`
	Comm       [16]uint8                   `json:"Comm"`
	Retval     dispatch_command_return     `json:"retval"`
}

func (this *MysqldEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Query); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Alllen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Retval); err != nil {
		return
	}
	return nil
}

func (this *MysqldEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  return:%s, Line:%s", this.Pid, this.Comm, this.Timestamp, this.Len, this.Alllen, this.Retval, unix.ByteSliceToString((this.Query[:]))))
	return s
}

func (this *MysqldEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  return:%s, Line:%s", this.Pid, this.Comm, this.Timestamp, this.Len, this.Alllen, this.Retval, unix.ByteSliceToString((this.Query[:]))))
	return s
}

func (this *MysqldEvent) Clone() IEventStruct {
	event := new(MysqldEvent)
	event.event_type = EventTypeOutput
	return event
}

func (this *MysqldEvent) EventType() EventType {
	return this.event_type
}

func (this *MysqldEvent) GetUUID() string {
	return fmt.Sprintf("%d_%s", this.Pid, this.Comm)
}

func (this *MysqldEvent) Payload() []byte {
	return this.Query[:this.Len]
}

func (this *MysqldEvent) PayloadLen() int {
	return int(this.Len)
}
