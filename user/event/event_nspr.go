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
)

type NsprDataEvent struct {
	eventType EventType
	DataType  int64             `json:"dataType"`
	Timestamp uint64            `json:"timestamp"`
	Pid       uint32            `json:"pid"`
	Tid       uint32            `json:"tid"`
	Data      [MaxDataSize]byte `json:"data"`
	DataLen   int32             `json:"dataLen"`
	Comm      [16]byte          `json:"Comm"`
}

func (ne *NsprDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ne.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ne.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ne.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ne.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ne.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ne.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ne.Comm); err != nil {
		return
	}
	return nil
}

func (ne *NsprDataEvent) StringHex() string {
	var perfix, packetType string
	switch AttachType(ne.DataType) {
	case ProbeEntry:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", ne.DataType)
	}

	var b *bytes.Buffer
	var s string
	// firefox 进程的通讯线程名为 Socket Thread
	var fire_thread = strings.TrimSpace(fmt.Sprintf("%s", ne.Comm[:13]))
	// disable filter default
	if false && strings.Compare(fire_thread, "Socket Thread") != 0 {
		b = bytes.NewBufferString(fmt.Sprintf("%s[ignore]%s", COLORBLUE, COLORRESET))
		s = fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:%s", ne.Pid, ne.Comm, packetType, ne.Tid, ne.DataLen, b.String())
	} else {
		b = dumpByteSlice(ne.Data[:ne.DataLen], perfix)
		b.WriteString(COLORRESET)
		s = fmt.Sprintf("PID:%d, Comm:%s, Type:%s, TID:%d, DataLen:%d bytes, Payload:\n%s", ne.Pid, ne.Comm, packetType, ne.Tid, ne.DataLen, b.String())
	}

	return s
}

func (ne *NsprDataEvent) String() string {
	var perfix, packetType string
	switch AttachType(ne.DataType) {
	case ProbeEntry:
		packetType = fmt.Sprintf("%sRecived%s", COLORGREEN, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		packetType = fmt.Sprintf("%sSend%s", COLORPURPLE, COLORRESET)
		perfix = COLORPURPLE
	default:
		packetType = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, ne.DataType, COLORRESET)
	}

	var b *bytes.Buffer
	// firefox 进程的通讯线程名为 Socket Thread
	// disable filter default
	if false && strings.TrimSpace(string(ne.Comm[:13])) != "Socket Thread" {
		b = bytes.NewBufferString("[ignore]")
	} else {
		b = bytes.NewBuffer(ne.Data[:ne.DataLen])
	}
	s := fmt.Sprintf(" PID:%d, Comm:%s, TID:%d, TYPE:%s, DataLen:%d bytes, Payload:\n%s%s%s", ne.Pid, ne.Comm, ne.Tid, packetType, ne.DataLen, perfix, b.String(), COLORRESET)
	return s
}

func (ne *NsprDataEvent) Clone() IEventStruct {
	event := new(NsprDataEvent)
	event.eventType = EventTypeEventProcessor
	return event
}

func (ne *NsprDataEvent) EventType() EventType {
	return ne.eventType
}

func (ne *NsprDataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d", ne.Pid, ne.Tid, ne.Comm, ne.DataType)
}

func (ne *NsprDataEvent) Payload() []byte {
	return ne.Data[:ne.DataLen]
}

func (ne *NsprDataEvent) PayloadLen() int {
	return int(ne.DataLen)
}
