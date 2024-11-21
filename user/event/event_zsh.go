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
	"strings"

	"golang.org/x/sys/unix"
)

/*
  u8 type;
  u32 pid;
  u32 uid;
  u8 line[MAX_DATA_SIZE_BASH];
  u32 retval;
  char comm[TASK_COMM_LEN];
*/

const MaxDataSizeZsh = 256

type ZshEvent struct {
	eventType EventType
	ZshType   uint32                `json:"zsh_type"`
	Pid       uint32                `json:"pid"`
	Uid       uint32                `json:"uid"`
	Comm      [16]byte              `json:"Comm"`
	Line      [MaxDataSizeZsh]uint8 `json:"line"`
}

func (be *ZshEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &be.ZshType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Uid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &be.Line); err != nil {
		return
	}
	return nil
}

func (be *ZshEvent) String() string {
	s := fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tLine:\n%s", be.Pid, be.Uid, be.Comm, strings.TrimSuffix(unix.ByteSliceToString(be.Line[:]), "\n"))
	return s
}

func (be *ZshEvent) StringHex() string {
	s := fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tLine:\n%s,", be.Pid, be.Uid, be.Comm, be.Line)
	return s
}

func (be *ZshEvent) Clone() IEventStruct {
	event := new(ZshEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (be *ZshEvent) EventType() EventType {
	return be.eventType
}

func (be *ZshEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s", be.Pid, be.Uid, be.Comm)
}

func (be *ZshEvent) Payload() []byte {
	return be.Line[:]
}

func (be *ZshEvent) PayloadLen() int {
	return len(be.Line)
}
