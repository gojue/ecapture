// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package gotls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// TLSDataEvent represents a TLS data read/write event from GoTLS
// This structure matches the eBPF event structure
type TLSDataEvent struct {
	Timestamp uint64     // Timestamp in nanoseconds
	Pid       uint32     // Process ID
	Tid       uint32     // Thread ID
	DataLen   uint32     // Length of actual data
	EventType uint8      // 0 = write, 1 = read
	Comm      [16]byte   // Process name
	Data      [4096]byte // TLS data buffer (max 4KB per event)
}

// DecodeFromBytes deserializes the event from raw eBPF data.
func (e *TLSDataEvent) DecodeFromBytes(data []byte) error {
	if len(data) < 32 { // Minimum size: 8+4+4+4+1+16 = 37, but eBPF struct alignment
		return errors.NewEventDecodeError("gotls.TLSDataEvent", fmt.Errorf("data too short: got %d bytes", len(data)))
	}

	buf := bytes.NewBuffer(data)

	// Read timestamp
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return errors.NewEventDecodeError("gotls.Timestamp", err)
	}

	// Read PID
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("gotls.Pid", err)
	}

	// Read TID
	if err := binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return errors.NewEventDecodeError("gotls.Tid", err)
	}

	// Read data length
	if err := binary.Read(buf, binary.LittleEndian, &e.DataLen); err != nil {
		return errors.NewEventDecodeError("gotls.DataLen", err)
	}

	// Read event type
	if err := binary.Read(buf, binary.LittleEndian, &e.EventType); err != nil {
		return errors.NewEventDecodeError("gotls.EventType", err)
	}

	// Read comm
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("gotls.Comm", err)
	}

	// Read data
	if e.DataLen > 4096 {
		e.DataLen = 4096
	}

	remaining := buf.Len()
	if remaining > 0 {
		if remaining > 4096 {
			remaining = 4096
		}
		copy(e.Data[:], buf.Next(remaining))
	}

	return nil
}

// GetTimestamp returns the event timestamp as time.Time
func (e *TLSDataEvent) GetTimestamp() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

// GetPid returns the process ID
func (e *TLSDataEvent) GetPid() uint32 {
	return e.Pid
}

// GetData returns the TLS data
func (e *TLSDataEvent) GetData() []byte {
	dataLen := e.DataLen
	if dataLen > 4096 {
		dataLen = 4096
	}
	return e.Data[:dataLen]
}

// IsRead returns true if this is a read event
func (e *TLSDataEvent) IsRead() bool {
	return e.EventType == 1 // GOTLS_EVENT_TYPE_READ
}

// IsWrite returns true if this is a write event
func (e *TLSDataEvent) IsWrite() bool {
	return e.EventType == 0 // GOTLS_EVENT_TYPE_WRITE
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

// String returns a human-readable representation of the event.
func (e *TLSDataEvent) String() string {
	direction := "write"
	if e.IsRead() {
		direction = "read"
	}

	return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, Type:%s, Len:%d\nData:\n%s",
		e.Pid, e.Tid, commToString(e.Comm[:]), direction, e.DataLen, string(e.GetData()))
}

// StringHex returns a hexadecimal representation of the event.
func (e *TLSDataEvent) StringHex() string {
	direction := "write"
	if e.IsRead() {
		direction = "read"
	}

	hexData := fmt.Sprintf("%x", e.GetData())
	return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, Type:%s, Len:%d\nData(hex):\n%s",
		e.Pid, e.Tid, commToString(e.Comm[:]), direction, e.DataLen, hexData)
}

// Clone creates a new instance of the event.
func (e *TLSDataEvent) Clone() domain.Event {
	return &TLSDataEvent{}
}

// Type returns the event type (always Output for TLS data events).
func (e *TLSDataEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event.
func (e *TLSDataEvent) UUID() string {
	return fmt.Sprintf("%d_%d_%s_%d", e.Pid, e.Tid, commToString(e.Comm[:]), e.Timestamp)
}

// Validate checks if the event data is valid.
func (e *TLSDataEvent) Validate() error {
	if e.DataLen > 4096 {
		return fmt.Errorf("data length %d exceeds maximum 4096", e.DataLen)
	}
	return nil
}
