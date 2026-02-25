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

// GoTLSDataEvent represents a TLS data read/write event from GoTLS
// This structure matches the eBPF event structure: struct go_tls_event
type GoTLSDataEvent struct {
	Timestamp   uint64   `json:"timestamp"` // Nanosecond timestamp
	Pid         uint32   `json:"pid"`       // Process ID
	Tid         uint32   `json:"tid"`       // Thread ID
	DataLen     int32    `json:"dataLen"`   // Length of actual data
	PayloadType uint8    `json:"payloadType"`
	Comm        [16]byte `json:"comm"` // Process name
	Data        []byte   `json:"data"` // TLS data payload

	DataType uint8  `json:"dataType"`
	Fd       uint32 `json:"fd"`
}

// DecodeFromBytes deserializes the event from raw eBPF data.
func (e *GoTLSDataEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read fields in order matching the eBPF structure
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return errors.NewEventDecodeError("gotls.Timestamp", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("gotls.Pid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return errors.NewEventDecodeError("gotls.Tid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.DataLen); err != nil {
		return errors.NewEventDecodeError("gotls.DataLen", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.PayloadType); err != nil {
		return errors.NewEventDecodeError("gotls.PayloadType", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("gotls.Comm", err)
	}

	if e.DataLen > 0 {
		e.Data = make([]byte, e.DataLen)
		if err := binary.Read(buf, binary.LittleEndian, &e.Data); err != nil {
			return errors.NewEventDecodeError("gotls.Data", err)
		}
	} else {
		e.DataLen = 0
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("gotls.Comm", err)
	}

	if e.Timestamp == 0 {
		e.Timestamp = uint64(time.Now().UnixNano())
	}
	return nil
}

// GetTimestamp returns the event timestamp in nanoseconds
func (e *GoTLSDataEvent) GetTimestamp() uint64 {
	return e.Timestamp
}

// GetTimestampTime returns the event timestamp as time.Time
func (e *GoTLSDataEvent) GetTimestampTime() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

// GetPid returns the process ID
func (e *GoTLSDataEvent) GetPid() uint32 {
	return e.Pid
}

// GetComm returns the process name as a string (compatible with handlers.TLSDataEvent interface)
func (e *GoTLSDataEvent) GetComm() string {
	return commToString(e.Comm[:])
}

// GetData returns the TLS data
func (e *GoTLSDataEvent) GetData() []byte {
	dataLen := e.DataLen
	if dataLen < 0 {
		dataLen = 0
	}
	if dataLen > 16384 {
		dataLen = 16384
	}
	return e.Data[:dataLen]
}

// GetDataLen returns the length of the TLS data (compatible with handlers.TLSDataEvent interface)
func (e *GoTLSDataEvent) GetDataLen() uint32 {
	if e.DataLen < 0 {
		return 0
	}
	return uint32(e.DataLen)
}

// IsRead returns true if this is a read event
func (e *GoTLSDataEvent) IsRead() bool {
	return e.DataType == 1 // GOTLS_EVENT_TYPE_READ
}

// IsWrite returns true if this is a write event
func (e *GoTLSDataEvent) IsWrite() bool {
	return e.DataType == 0 // GOTLS_EVENT_TYPE_WRITE
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
func (e *GoTLSDataEvent) String() string {
	direction := "write"
	if e.IsRead() {
		direction = "read"
	}

	return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, Type:%s, Len:%d\nData:\n%s",
		e.Pid, e.Tid, commToString(e.Comm[:]), direction, e.DataLen, string(e.GetData()))
}

// StringHex returns a hexadecimal representation of the event.
func (e *GoTLSDataEvent) StringHex() string {
	direction := "write"
	if e.IsRead() {
		direction = "read"
	}

	hexData := fmt.Sprintf("%x", e.GetData())
	return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, Type:%s, Len:%d\nData(hex):\n%s",
		e.Pid, e.Tid, commToString(e.Comm[:]), direction, e.DataLen, hexData)
}

// Clone creates a new instance of the event.
func (e *GoTLSDataEvent) Clone() domain.Event {
	return &GoTLSDataEvent{}
}

// Type returns the event type (always Output for TLS data events).
func (e *GoTLSDataEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event.
func (e *GoTLSDataEvent) UUID() string {
	return fmt.Sprintf("%d_%d_%s_%d", e.Pid, e.Tid, e.GetComm(), e.Timestamp)
}

// Validate checks if the event data is valid.
func (e *GoTLSDataEvent) Validate() error {
	if e.DataLen > 16384 {
		return fmt.Errorf("data length %d exceeds maximum 16384", e.DataLen)
	}
	if e.DataLen < 0 {
		return fmt.Errorf("data length %d is negative", e.DataLen)
	}
	return nil
}
