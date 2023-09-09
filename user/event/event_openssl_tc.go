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
)

const (
	TaskCommLen = 16
	CmdlineLen  = 256
)

type TcSkbEvent struct {
	eventType EventType
	Ts        uint64            `json:"ts"`
	Pid       uint32            `json:"pid"`
	Comm      [TaskCommLen]byte `json:"Comm"`
	Cmdline   [CmdlineLen]byte  `json:"Cmdline"`
	Len       uint32            `json:"len"`
	Ifindex   uint32            `json:"ifindex"`
	payload   []byte
}

func (te *TcSkbEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &te.Ts); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &te.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &te.Comm); err != nil {
		return
	}
	//if err = binary.Read(buf, binary.LittleEndian, &te.Cmdline); err != nil {
	//	return
	//}
	//TODO
	te.Cmdline[0] = 91 //ascii 91
	if err = binary.Read(buf, binary.LittleEndian, &te.Len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &te.Ifindex); err != nil {
		return
	}
	tmpData := make([]byte, te.Len)
	if err = binary.Read(buf, binary.LittleEndian, &tmpData); err != nil {
		return
	}
	te.payload = tmpData
	return nil
}

func (te *TcSkbEvent) StringHex() string {
	b := dumpByteSlice(te.payload, COLORGREEN)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:%s", te.Pid, te.Comm, te.Len, te.Ifindex, b.String())
	return s
}

func (te *TcSkbEvent) String() string {

	s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:[internal data]", te.Pid, te.Comm, te.Len, te.Ifindex)
	return s
}

func (te *TcSkbEvent) Clone() IEventStruct {
	event := new(TcSkbEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (te *TcSkbEvent) EventType() EventType {
	return te.eventType
}

func (te *TcSkbEvent) GetUUID() string {
	return fmt.Sprintf("%d-%d-%s", te.Pid, te.Ifindex, te.Comm)
}

func (te *TcSkbEvent) Payload() []byte {
	return te.payload
}

func (te *TcSkbEvent) PayloadLen() int {
	return int(te.Len)
}
