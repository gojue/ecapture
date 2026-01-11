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

package openssl

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	TaskCommLen = 16
	CmdlineLen  = 256
)

// PacketEvent represents a network packet captured by TC probes.
// This implements the PacketEvent interface from handlers package.
type PacketEvent struct {
	Timestamp      uint64
	Pid            uint32
	Comm           [TaskCommLen]byte
	Cmdline        [CmdlineLen]byte
	PacketLen      uint32
	InterfaceIndex uint32
	PacketData     []byte
}

// DecodeFromBytes decodes a packet event from raw bytes.
func (e *PacketEvent) DecodeFromBytes(data []byte) error {
	if len(data) < 36 {
		return errors.New(errors.ErrCodeEventDecode, "packet event data too short")
	}
	var err error
	buf := bytes.NewBuffer(data)
	if err = binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return err
	}
	//if err = binary.Read(buf, binary.LittleEndian, &te.Cmdline); err != nil {
	//	return
	//}
	//TODO
	e.Cmdline[0] = 91 //ascii 91
	if err = binary.Read(buf, binary.LittleEndian, &e.PacketLen); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.InterfaceIndex); err != nil {
		return err
	}
	tmpData := make([]byte, e.PacketLen)
	if err = binary.Read(buf, binary.LittleEndian, &tmpData); err != nil {
		return err
	}
	e.PacketData = tmpData
	return nil
}

// Validate checks if the event is valid.
func (e *PacketEvent) Validate() error {
	if e.PacketLen == 0 {
		return errors.New(errors.ErrCodeEventValidation, "packet length is zero")
	}
	return nil
}

// String returns a human-readable representation of the event.
func (e *PacketEvent) String() string {
	return fmt.Sprintf("Packet captured: len=%d bytes, timestamp=%d, interface=%d",
		e.PacketLen, e.Timestamp, e.InterfaceIndex)
}

// StringHex returns a hexadecimal representation of the event.
func (e *PacketEvent) StringHex() string {
	return e.String()
}

// Clone creates a copy of the event.
func (e *PacketEvent) Clone() domain.Event {
	clone := &PacketEvent{
		Timestamp:      e.Timestamp,
		PacketLen:      e.PacketLen,
		InterfaceIndex: e.InterfaceIndex,
	}
	if e.PacketData != nil {
		clone.PacketData = make([]byte, len(e.PacketData))
		copy(clone.PacketData, e.PacketData)
	}
	return clone
}

// Type returns the event type.
func (e *PacketEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for the event.
func (e *PacketEvent) UUID() string {
	return fmt.Sprintf("packet-%d", e.Timestamp)
}

// PacketEvent interface implementation for handlers.PacketEvent
func (e *PacketEvent) GetTimestamp() uint64 {
	return e.Timestamp
}

func (e *PacketEvent) GetPacketData() []byte {
	return e.PacketData
}

func (e *PacketEvent) GetPacketLen() uint32 {
	return e.PacketLen
}

func (e *PacketEvent) GetInterfaceIndex() uint32 {
	return e.InterfaceIndex
}

// Connection tuple information - these would need to be parsed from packet data
// For now, return empty values as TC captures raw packets
func (e *PacketEvent) GetSrcIP() string {
	return ""
}

func (e *PacketEvent) GetDstIP() string {
	return ""
}

func (e *PacketEvent) GetSrcPort() uint16 {
	return 0
}

func (e *PacketEvent) GetDstPort() uint16 {
	return 0
}

// Decode implements domain.EventDecoder interface for packet events.
func (e *PacketEvent) Decode(data []byte) (domain.Event, error) {
	event := &PacketEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}
