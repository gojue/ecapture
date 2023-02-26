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

type GnutlsDataEvent struct {
	event_type EventType
	DataType   int64             `json:"dataType"`
	Timestamp  uint64            `json:"timestamp"`
	Pid        uint32            `json:"pid"`
	Tid        uint32            `json:"tid"`
	Data       [MaxDataSize]byte `json:"data"`
	Data_len   int32             `json:"data_len"`
	Comm       [16]byte          `json:"Comm"`
}

func (this *GnutlsDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Data_len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	return nil
}

func (this *GnutlsDataEvent) StringHex() string {
	var perfix, packetType string
	switch AttachType(this.DataType) {
	case ProbeEntry:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", this.DataType)
	}

	b := dumpByteSlice(this.Data[:this.Data_len], perfix)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:\n%s", this.Pid, this.Comm, packetType, this.Tid, this.Data_len, b.String())
	return s
}

func (this *GnutlsDataEvent) String() string {
	var perfix, packetType string
	switch AttachType(this.DataType) {
	case ProbeEntry:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = COLORPURPLE
	default:
		packetType = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, this.DataType, COLORRESET)
	}
	s := fmt.Sprintf(" PID:%d, Comm:%s, TID:%d, TYPE:%s, DataLen:%d bytes, Payload:\n%s%s%s", this.Pid, this.Comm, this.Tid, packetType, this.Data_len, perfix, string(this.Data[:this.Data_len]), COLORRESET)
	return s
}

func (this *GnutlsDataEvent) Clone() IEventStruct {
	event := new(GnutlsDataEvent)
	event.event_type = EventTypeEventProcessor
	return event
}

func (this *GnutlsDataEvent) EventType() EventType {
	return this.event_type
}

func (this *GnutlsDataEvent) GetUUID() string {
	//return fmt.Sprintf("%d_%d_%s", this.Pid, this.Tid, this.Comm)
	return fmt.Sprintf("%d_%d_%s_%d", this.Pid, this.Tid, this.Comm, this.DataType)
}

func (this *GnutlsDataEvent) Payload() []byte {
	return this.Data[:this.Data_len]
}

func (this *GnutlsDataEvent) PayloadLen() int {
	return int(this.Data_len)
}
