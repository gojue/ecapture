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

package gnutls

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
)

const packetEventHeaderSize = 8 + 4 + TaskCommLen + 4 + 4

// PacketEvent mirrors the variable-length skb_data_event_t sample emitted by
// kern/tc.h: a fixed 36-byte header followed by the captured packet bytes.
type PacketEvent struct {
	Timestamp      uint64
	Pid            uint32
	Comm           [TaskCommLen]byte
	PacketLen      uint32
	InterfaceIndex uint32
	PacketData     []byte
}

func (e *PacketEvent) DecodeFromBytes(data []byte) error {
	if len(data) < packetEventHeaderSize {
		return errors.New(errors.ErrCodeEventDecode,
			fmt.Sprintf("packet event too short: got %d, need at least %d", len(data), packetEventHeaderSize))
	}

	buf := bytes.NewReader(data)
	fields := []any{&e.Timestamp, &e.Pid, &e.Comm, &e.PacketLen, &e.InterfaceIndex}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field); err != nil {
			return errors.NewEventDecodeError("gnutls.PacketEvent", err)
		}
	}
	if uint64(e.PacketLen) > uint64(buf.Len()) {
		return errors.New(errors.ErrCodeEventDecode,
			fmt.Sprintf("packet payload truncated: header says %d bytes, sample has %d", e.PacketLen, buf.Len()))
	}

	e.PacketData = make([]byte, int(e.PacketLen))
	if _, err := buf.Read(e.PacketData); err != nil {
		return errors.NewEventDecodeError("gnutls.PacketData", err)
	}
	return nil
}

func (e *PacketEvent) Validate() error {
	if e.PacketLen == 0 {
		return errors.New(errors.ErrCodeEventValidation, "packet length is zero")
	}
	if uint32(len(e.PacketData)) != e.PacketLen {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("packet length mismatch: header=%d payload=%d", e.PacketLen, len(e.PacketData)))
	}
	return nil
}

func (e *PacketEvent) String() string {
	return fmt.Sprintf("Packet captured: len=%d bytes, timestamp=%d, interface=%d",
		e.PacketLen, e.Timestamp, e.InterfaceIndex)
}

func (e *PacketEvent) StringHex() string {
	return e.String()
}

func (e *PacketEvent) Clone() domain.Event {
	clone := *e
	clone.PacketData = append([]byte(nil), e.PacketData...)
	return &clone
}

func (e *PacketEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (e *PacketEvent) UUID() string {
	return fmt.Sprintf("gnutls-packet-%d-%d", e.Timestamp, e.InterfaceIndex)
}

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
