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

package zsh

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	MaxDataSizeZsh       = 256
	ZshEventTypeReadline = 0
)

// Event represents a Zsh command event from eBPF.
type Event struct {
	ZshType uint32                `json:"zsh_type"`
	Pid     uint32                `json:"pid"`
	Uid     uint32                `json:"uid"`
	Comm    [16]byte              `json:"comm"`
	Line    [MaxDataSizeZsh]uint8 `json:"line"`
}

// DecodeFromBytes decodes the event from raw bytes.
func (e *Event) DecodeFromBytes(data []byte) error {
	if len(data) == 0 {
		return errors.NewEventDecodeError("zsh event", fmt.Errorf("empty data"))
	}

	buf := bytes.NewBuffer(data)

	if err := binary.Read(buf, binary.LittleEndian, &e.ZshType); err != nil {
		return errors.NewEventDecodeError("zsh event: ZshType", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("zsh event: Pid", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Uid); err != nil {
		return errors.NewEventDecodeError("zsh event: Uid", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("zsh event: Comm", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Line); err != nil {
		return errors.NewEventDecodeError("zsh event: Line", err)
	}

	return nil
}

// Validate checks if the event data is valid.
func (e *Event) Validate() error {
	// Zsh events are always valid if decoded successfully
	return nil
}

// String returns a formatted string representation of the event.
func (e *Event) String() string {
	line := strings.TrimSuffix(unix.ByteSliceToString(e.Line[:]), "\n")
	return fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tLine:\n%s",
		e.Pid, e.Uid, commToString(e.Comm[:]), line)
}

// StringHex returns a hexadecimal representation of the event.
func (e *Event) StringHex() string {
	line := strings.TrimSuffix(unix.ByteSliceToString(e.Line[:]), "\n")
	hexData := fmt.Sprintf("%x", []byte(line))
	return fmt.Sprintf("PID:%d, UID:%d, \tComm:%s, \tLine(hex):\n%s",
		e.Pid, e.Uid, commToString(e.Comm[:]), hexData)
}

// Clone creates a new instance of the event.
func (e *Event) Clone() domain.Event {
	return &Event{}
}

// Type returns the event type (always Output for zsh commands).
func (e *Event) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event.
func (e *Event) UUID() string {
	return fmt.Sprintf("%d_%d_%s", e.Pid, e.Uid, commToString(e.Comm[:]))
}

// Bytes serializes the event to JSON bytes.
func (e *Event) Bytes() []byte {
	b, err := json.Marshal(e)
	if err != nil {
		return []byte{}
	}
	return b
}

// commToString converts a null-terminated byte array to string.
func commToString(comm []byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}
