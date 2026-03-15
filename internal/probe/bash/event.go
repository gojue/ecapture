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

package bash

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	// BashEventTypeReadline indicates a readline event
	BashEventTypeReadline = 0
	// BashEventTypeRetval indicates a return value event
	BashEventTypeRetval = 1
	// BashEventTypeExitOrExec indicates an exit or exec event
	BashEventTypeExitOrExec = 2

	// MaxDataSizeBash is the maximum line size from eBPF
	MaxDataSizeBash = 256
)

// Event represents a bash command event from eBPF.
type Event struct {
	BashType    uint32
	Pid         uint32
	Uid         uint32
	Line        [MaxDataSizeBash]uint8
	ReturnValue uint32
	Comm        [16]byte
	AllLines    string // Accumulated lines for multi-line commands
}

// DecodeFromBytes deserializes the event from raw eBPF data.
func (e *Event) DecodeFromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read fields in order matching the eBPF structure
	if err := binary.Read(buf, binary.LittleEndian, &e.BashType); err != nil {
		return errors.NewEventDecodeError("bash.BashType", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("bash.Pid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Uid); err != nil {
		return errors.NewEventDecodeError("bash.Uid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Line); err != nil {
		return errors.NewEventDecodeError("bash.Line", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.ReturnValue); err != nil {
		return errors.NewEventDecodeError("bash.ReturnValue", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("bash.Comm", err)
	}

	return nil
}

// String returns a human-readable representation of the event.
func (e *Event) String() string {
	if e.AllLines == "" {
		return ""
	}
	return fmt.Sprintf("PID:%d, UID:%d, Comm:%s, Retvalue:%d, Line:\n%s",
		e.Pid, e.Uid, commToString(e.Comm[:]), e.ReturnValue, e.AllLines)
}

// StringHex returns a hexadecimal representation of the event.
func (e *Event) StringHex() string {
	if e.AllLines == "" {
		return ""
	}
	hexData := fmt.Sprintf("%x", []byte(e.AllLines))
	return fmt.Sprintf("PID:%d, UID:%d, Comm:%s, Retvalue:%d, Line(hex):\n%s",
		e.Pid, e.Uid, commToString(e.Comm[:]), e.ReturnValue, hexData)
}

// Clone creates a new instance of the event.
func (e *Event) Clone() domain.Event {
	return &Event{}
}

// Type returns the event type (always Output for bash commands).
func (e *Event) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event.
func (e *Event) UUID() string {
	return fmt.Sprintf("%d_%d_%s", e.Pid, e.Uid, commToString(e.Comm[:]))
}

// Validate checks if the event data is valid.
func (e *Event) Validate() error {
	// Bash events are always valid if decoded successfully
	return nil
}

// commToString converts a null-terminated byte array to string.
func commToString(comm []byte) string {
	// Find null terminator
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}
