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
	eventType EventType
	DataType  int64             `json:"dataType"`
	Timestamp uint64            `json:"timestamp"`
	Pid       uint32            `json:"pid"`
	Tid       uint32            `json:"tid"`
	Data      [MaxDataSize]byte `json:"data"`
	DataLen   int32             `json:"data_len"`
	Comm      [16]byte          `json:"Comm"`
}

func (ge *GnutlsDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ge.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ge.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ge.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ge.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ge.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ge.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ge.Comm); err != nil {
		return
	}
	return nil
}

func (ge *GnutlsDataEvent) StringHex() string {
	var perfix, packetType string
	switch AttachType(ge.DataType) {
	case ProbeEntry:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", ge.DataType)
	}

	b := dumpByteSlice(ge.Data[:ge.DataLen], perfix)
	b.WriteString(COLORRESET)
	s := fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:\n%s", ge.Pid, ge.Comm, packetType, ge.Tid, ge.DataLen, b.String())
	return s
}

func (ge *GnutlsDataEvent) String() string {
	var perfix, packetType string
	switch AttachType(ge.DataType) {
	case ProbeEntry:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = COLORPURPLE
	default:
		packetType = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, ge.DataType, COLORRESET)
	}
	s := fmt.Sprintf(" PID:%d, Comm:%s, TID:%d, TYPE:%s, DataLen:%d bytes, Payload:\n%s%s%s", ge.Pid, ge.Comm, ge.Tid, packetType, ge.DataLen, perfix, string(ge.Data[:ge.DataLen]), COLORRESET)
	return s
}

func (ge *GnutlsDataEvent) Clone() IEventStruct {
	event := new(GnutlsDataEvent)
	event.eventType = EventTypeEventProcessor
	return event
}

func (ge *GnutlsDataEvent) EventType() EventType {
	return ge.eventType
}

func (ge *GnutlsDataEvent) GetUUID() string {
	//return fmt.Sprintf("%d_%d_%s", ge.Pid, ge.Tid, ge.Comm)
	return fmt.Sprintf("%d_%d_%s_%d", ge.Pid, ge.Tid, ge.Comm, ge.DataType)
}

func (ge *GnutlsDataEvent) Payload() []byte {
	return ge.Data[:ge.DataLen]
}

func (ge *GnutlsDataEvent) PayloadLen() int {
	return int(ge.DataLen)
}
