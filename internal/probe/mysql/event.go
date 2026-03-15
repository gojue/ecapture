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

package mysql

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/internal/domain"
)

const (
	// MaxDataSize is the maximum size of query data captured
	MaxDataSize = 256

	// Dispatch command return values
	DispatchCommandV57Failed       = -2
	DispatchCommandNotCaptured     = -1
	DispatchCommandSuccess         = 0
	DispatchCommandCloseConnection = 1
	DispatchCommandWouldblock      = 2
)

// DispatchCommandReturn represents the return value of dispatch_command
type DispatchCommandReturn int8

// String returns the string representation of dispatch command return value
func (d DispatchCommandReturn) String() string {
	switch d {
	case DispatchCommandCloseConnection:
		return "CLOSE_CONNECTION"
	case DispatchCommandSuccess:
		return "SUCCESS"
	case DispatchCommandWouldblock:
		return "WOULDBLOCK"
	case DispatchCommandNotCaptured:
		return "NOT_CAPTURED"
	case DispatchCommandV57Failed:
		return "V57_FAILED"
	default:
		return "UNKNOWN"
	}
}

// Event represents a MySQL query event captured from eBPF
// This struct matches the kernel-side data_t structure
type Event struct {
	Pid       uint64                `json:"pid"`
	Timestamp uint64                `json:"timestamp"`
	Query     [MaxDataSize]uint8    `json:"query"`
	Alllen    uint64                `json:"alllen"`
	Len       uint64                `json:"len"`
	Comm      [16]uint8             `json:"comm"`
	Retval    DispatchCommandReturn `json:"retval"`
}

// DecodeFromBytes decodes the event from raw bytes
func (e *Event) DecodeFromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return fmt.Errorf("failed to read Pid: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return fmt.Errorf("failed to read Timestamp: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Query); err != nil {
		return fmt.Errorf("failed to read Query: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Alllen); err != nil {
		return fmt.Errorf("failed to read Alllen: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Len); err != nil {
		return fmt.Errorf("failed to read Len: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return fmt.Errorf("failed to read Comm: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &e.Retval); err != nil {
		return fmt.Errorf("failed to read Retval: %w", err)
	}

	return nil
}

// String returns a human-readable string representation of the event
func (e *Event) String() string {
	return fmt.Sprintf("MySQL Query[PID=%d, Comm=%s, Len=%d/%d, Status=%s]: %s",
		e.Pid,
		unix.ByteSliceToString(e.Comm[:]),
		e.Len,
		e.Alllen,
		e.Retval.String(),
		unix.ByteSliceToString(e.Query[:e.Len]),
	)
}

// StringHex returns a hex representation of the event (same as String for MySQL)
func (e *Event) StringHex() string {
	return e.String()
}

// Clone creates a new instance of the event
func (e *Event) Clone() domain.Event {
	return &Event{}
}

// Type returns the event type identifier
func (e *Event) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for the event
func (e *Event) UUID() string {
	return fmt.Sprintf("%d_%s_%d", e.Pid, unix.ByteSliceToString(e.Comm[:]), e.Timestamp)
}

// Validate validates the event data
func (e *Event) Validate() error {
	// Check if query length is valid
	if e.Len > MaxDataSize {
		return fmt.Errorf("query length %d exceeds maximum %d", e.Len, MaxDataSize)
	}

	// Check if query length doesn't exceed alllen
	if e.Len > e.Alllen {
		return fmt.Errorf("query length %d exceeds total length %d", e.Len, e.Alllen)
	}

	return nil
}

// GetPID returns the process ID
func (e *Event) GetPID() uint64 {
	return e.Pid
}

// GetComm returns the process command name
func (e *Event) GetComm() string {
	return unix.ByteSliceToString(e.Comm[:])
}

// GetQuery returns the SQL query string
func (e *Event) GetQuery() string {
	return unix.ByteSliceToString(e.Query[:e.Len])
}

// GetQueryLen returns the length of the captured query
func (e *Event) GetQueryLen() uint64 {
	return e.Len
}

// GetTotalQueryLen returns the total length of the query (may be truncated)
func (e *Event) GetTotalQueryLen() uint64 {
	return e.Alllen
}

// IsTruncated returns true if the query was truncated
func (e *Event) IsTruncated() bool {
	return e.Len < e.Alllen
}

// GetReturnValue returns the dispatch command return value
func (e *Event) GetReturnValue() DispatchCommandReturn {
	return e.Retval
}
