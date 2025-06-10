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
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const MaxDataSize = 1024 * 16 // fix: https://github.com/gojue/ecapture/issues/740

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
	return fmt.Sprintf("TLS_VERSION_UNKNOWN_%d", t.Version)
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
	Tuple     string
	BioType   uint32
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
	if err = binary.Read(buf, binary.LittleEndian, &se.BioType); err != nil {
		return
	}

	decodedKtime, err := DecodeKtime(int64(se.Timestamp), true)
	if err == nil {
		se.Timestamp = uint64(decodedKtime.Unix())
	}
	return nil
}

func commStr(comm []byte) string {
	return strings.TrimSpace(CToGoString(comm))
}

func (se *SSLDataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d_%s", se.Pid, se.Tid, commStr(se.Comm[:]), se.Fd, se.DataType, se.Tuple)
}

func (se *SSLDataEvent) Payload() []byte {
	return se.Data[:se.DataLen]
}

func (se *SSLDataEvent) PayloadLen() int {
	return int(se.DataLen)
}

func (se *SSLDataEvent) StringHex() string {
	var prefix string
	switch AttachType(se.DataType) {
	case ProbeEntry:
		prefix = COLORGREEN
	case ProbeRet:
		prefix = COLORPURPLE
	default:
	}

	b := dumpByteSlice(se.Data[:se.DataLen], prefix)
	b.WriteString(COLORRESET)

	s := fmt.Sprintf("%s, Payload:\n%s", se.BaseInfo(), b.String())
	return s
}

func (se *SSLDataEvent) String() string {
	var prefix string
	switch AttachType(se.DataType) {
	case ProbeEntry:
		prefix = COLORGREEN
	case ProbeRet:
		prefix = COLORPURPLE
	default:
	}
	s := fmt.Sprintf("%s, Payload:\n%s%s%s", se.BaseInfo(), prefix, string(se.Data[:se.DataLen]), COLORRESET)
	return s
}

func (se *SSLDataEvent) BaseInfo() string {
	addr := "[TODO]"
	if se.Tuple != "" {
		addr = se.Tuple
	}
	var connInfo string
	switch AttachType(se.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("%sReceived %d%s bytes from %s%s%s", COLORGREEN, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
	case ProbeRet:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
	default:
		connInfo = fmt.Sprintf("%sUNKNOWN_%d%s", COLORRED, se.DataType, COLORRESET)
	}
	v := TlsVersion{Version: se.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, Version:%s, %s", se.Pid, commStr(se.Comm[:]), se.Tid, v.String(), connInfo)
	return s
}

func (se *SSLDataEvent) Clone() IEventStruct {
	event := new(SSLDataEvent)
	event.eventType = EventTypeModuleData //EventTypeEventProcessor
	return event
}

func (se *SSLDataEvent) EventType() EventType {
	return se.eventType
}

type connDataEvent struct {
	Saddr       [16]byte `json:"saddr"`
	Daddr       [16]byte `json:"daddr"`
	Comm        [16]byte `json:"Comm"`
	TimestampNs uint64   `json:"timestampNs"`
	Sock        uint64   `json:"sock"`
	Pid         uint32   `json:"pid"`
	Tid         uint32   `json:"tid"`
	Fd          uint32   `json:"fd"`
	Family      uint16   `json:"family"`
	Sport       uint16   `json:"sport"`
	Dport       uint16   `json:"dport"`
	IsDestroy   uint8    `json:"isDestroy"`
	Pad         [7]byte  `json:"-"`

	// NOTE: do not leave padding hole in this struct.
}
type ConnDataEvent struct {
	eventType EventType
	connDataEvent
	Tuple string `json:"tuple"`
}

func (ce *ConnDataEvent) Decode(payload []byte) (err error) {
	data := unsafe.Slice((*byte)(unsafe.Pointer(&ce.connDataEvent)), int(unsafe.Sizeof(ce.connDataEvent)))
	copy(data, payload)

	if ce.Family == unix.AF_INET {
		saddr, daddr := netip.AddrFrom4([4]byte(ce.Saddr[:4])), netip.AddrFrom4([4]byte(ce.Daddr[:4]))
		ce.Tuple = fmt.Sprintf("%s:%d-%s:%d", saddr, ce.Sport, daddr, ce.Dport)
	} else {
		saddr, daddr := netip.AddrFrom16(ce.Saddr), netip.AddrFrom16(ce.Daddr)
		ce.Tuple = fmt.Sprintf("[%s]:%d-[%s]:%d", saddr, ce.Sport, daddr, ce.Dport)
	}

	return nil
}

func (ce *ConnDataEvent) StringHex() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Tuple: %s", ce.Pid, commStr(ce.Comm[:]), ce.Tid, ce.Fd, ce.Tuple)
	return s
}

func (ce *ConnDataEvent) String() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Tuple: %s", ce.Pid, commStr(ce.Comm[:]), ce.Tid, ce.Fd, ce.Tuple)
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
	// 临时沿用旧版 UUID 逻辑，新特性尚在开发中。
	return fmt.Sprintf("%d_%d_%s_%d", ce.Pid, ce.Tid, commStr(ce.Comm[:]), ce.Fd)

	// TODO: 新版 UUID 逻辑待启用。新格式增加了 socket 前缀，用于标识与套接字的绑定。
	// return fmt.Sprintf("%s:%d_%d_%s_%d", SocketLifecycleUUIDPrefix, ce.Pid, ce.Tid, commStr(ce.Comm[:]), ce.Fd)
}

func (ce *ConnDataEvent) Payload() []byte {
	return []byte(ce.Tuple)
}

func (ce *ConnDataEvent) PayloadLen() int {
	return len(ce.Tuple)
}
