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
)

type TcSkbEvent struct {
	event_type EventType
	Ts         uint64            `json:"ts"`
	Pid        uint32            `json:"pid"`
	Comm       [TaskCommLen]byte `json:"Comm"`
	Len        uint32            `json:"len"`
	Ifindex    uint32            `json:"ifindex"`
	payload    []byte
}

func (this *TcSkbEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Ts); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Ifindex); err != nil {
		return
	}
	tmpData := make([]byte, this.Len)
	if err = binary.Read(buf, binary.LittleEndian, &tmpData); err != nil {
		return
	}
	this.payload = tmpData
	return nil
}

func (this *TcSkbEvent) StringHex() string {
	b := dumpByteSlice(this.payload, COLORGREEN)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:%s", this.Pid, this.Comm, this.Len, this.Ifindex, b.String())
	return s
}

func (this *TcSkbEvent) String() string {

	s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:[internal data]", this.Pid, this.Comm, this.Len, this.Ifindex)
	return s
}

func (this *TcSkbEvent) Clone() IEventStruct {
	event := new(TcSkbEvent)
	event.event_type = EventTypeModuleData
	return event
}

func (this *TcSkbEvent) EventType() EventType {
	return this.event_type
}

func (this *TcSkbEvent) GetUUID() string {
	return fmt.Sprintf("%d-%d-%s", this.Pid, this.Ifindex, this.Comm)
}

func (this *TcSkbEvent) Payload() []byte {
	return this.payload
}

func (this *TcSkbEvent) PayloadLen() int {
	return int(this.Len)
}
