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
	"net"
)

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const MaxDataSize = 1024 * 4
const SaDataLen = 14

const (
	Ssl2Version   = 0x0002
	Ssl3Version   = 0x0300
	Tls1Version   = 0x0301
	Tls11Version  = 0x0302
	Tls12Version  = 0x0303
	Tls13Version  = 0x0304
	Dtls1Version  = 0xFEFF
	Dtls12Version = 0xFEFD
)

type TlsVersion struct {
	Version int32
}

func (t TlsVersion) String() string {
	switch t.Version {
	case Ssl2Version:
		return "SSL2_VERSION"
	case Ssl3Version:
		return "SSL3_VERSION"
	case Tls1Version:
		return "TLS1_VERSION"
	case Tls11Version:
		return "TLS1_1_VERSION"
	case Tls12Version:
		return "TLS1_2_VERSION"
	case Tls13Version:
		return "TLS1_3_VERSION"
	case Dtls1Version:
		return "DTLS1_VERSION"
	case Dtls12Version:
		return "DTLS1_2_VERSION"
	}
	return fmt.Sprintf("TLS_VERSION_UNKNOW_%d", t.Version)
}

type SSLDataEvent struct {
	eventType EventType
	DataType  int64             `json:"dataType"`
	Timestamp uint64            `json:"timestamp"`
	Pid       uint32            `json:"pid"`
	Tid       uint32            `json:"tid"`
	Data      [MaxDataSize]byte `json:"data"`
	DataLen   int32             `json:"dataLen"`
	Comm      [16]byte          `json:"Comm"`
	Fd        uint32            `json:"fd"`
	Version   int32             `json:"version"`
}

func (se *SSLDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &se.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Version); err != nil {
		return
	}

	return nil
}

func (se *SSLDataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", se.Pid, se.Tid, CToGoString(se.Comm[:]), se.Fd, se.DataType)
}

func (se *SSLDataEvent) Payload() []byte {
	return se.Data[:se.DataLen]
}

func (se *SSLDataEvent) PayloadLen() int {
	return int(se.DataLen)
}

func (se *SSLDataEvent) StringHex() string {
	//addr := se.module.(*module.MOpenSSLProbe).GetConn(se.Pid, se.Fd)
	addr := "[TODO]"
	var perfix, connInfo string
	switch AttachType(se.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sRecived %d%s bytes from %s%s%s", COLORGREEN, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", se.DataType)
	}

	b := dumpByteSlice(se.Data[:se.DataLen], perfix)
	b.WriteString(COLORRESET)

	v := TlsVersion{Version: se.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Payload:\n%s", se.Pid, CToGoString(se.Comm[:]), se.Tid, connInfo, v.String(), b.String())
	return s
}

func (se *SSLDataEvent) String() string {
	//addr := se.module.(*module.MOpenSSLProbe).GetConn(se.Pid, se.Fd)
	addr := "[TODO]"
	var perfix, connInfo string
	switch AttachType(se.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sRecived %d%s bytes from %s%s%s", COLORGREEN, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORGREEN
	case ProbeRet:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORPURPLE
	default:
		connInfo = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, se.DataType, COLORRESET)
	}
	v := TlsVersion{Version: se.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, Version:%s, %s, Payload:\n%s%s%s", se.Pid, bytes.TrimSpace(se.Comm[:]), se.Tid, v.String(), connInfo, perfix, string(se.Data[:se.DataLen]), COLORRESET)
	return s
}

func (se *SSLDataEvent) Clone() IEventStruct {
	event := new(SSLDataEvent)
	event.eventType = EventTypeEventProcessor
	return event
}

func (se *SSLDataEvent) EventType() EventType {
	return se.eventType
}

//  connect_events map
/*
uint64_t timestamp_ns;
  uint32_t pid;
  uint32_t tid;
  uint32_t fd;
  char sa_data[SA_DATA_LEN];
  char Comm[TASK_COMM_LEN];
*/
type ConnDataEvent struct {
	eventType   EventType
	TimestampNs uint64          `json:"timestampNs"`
	Pid         uint32          `json:"pid"`
	Tid         uint32          `json:"tid"`
	Fd          uint32          `json:"fd"`
	SaData      [SaDataLen]byte `json:"saData"`
	Comm        [16]byte        `json:"Comm"`
	Addr        string          `json:"addr"`
}

func (ce *ConnDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ce.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.SaData); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Comm); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(ce.SaData[0:2])
	ip := net.IPv4(ce.SaData[2], ce.SaData[3], ce.SaData[4], ce.SaData[5])
	ce.Addr = fmt.Sprintf("%s:%d", ip, port)
	return nil
}

func (ce *ConnDataEvent) StringHex() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s", ce.Pid, bytes.TrimSpace(ce.Comm[:]), ce.Tid, ce.Fd, ce.Addr)
	return s
}

func (ce *ConnDataEvent) String() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s", ce.Pid, bytes.TrimSpace(ce.Comm[:]), ce.Tid, ce.Fd, ce.Addr)
	return s
}

func (ce *ConnDataEvent) Clone() IEventStruct {
	event := new(ConnDataEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (ce *ConnDataEvent) EventType() EventType {
	return ce.eventType
}

func (ce *ConnDataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d", ce.Pid, ce.Tid, bytes.TrimSpace(ce.Comm[:]), ce.Fd)
}

func (ce *ConnDataEvent) Payload() []byte {
	return []byte(ce.Addr)
}

func (ce *ConnDataEvent) PayloadLen() int {
	return len(ce.Addr)
}
