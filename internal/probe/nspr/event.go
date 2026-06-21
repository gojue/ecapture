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

package nspr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	// DataType constants matching C enum ssl_data_event_type
	DataTypeRead  = 0
	DataTypeWrite = 1

	// MaxDataSize is the maximum size of TLS data payload
	// Must match MAX_DATA_SIZE_OPENSSL in kern/common.h
	MaxDataSize = 1024 * 16 // 16384

	// TaskCommLen is the maximum length of the process command name
	// Must match TASK_COMM_LEN in kern/common.h
	TaskCommLen = 16
)

// TLSDataEvent represents a TLS data event from NSPR/NSS eBPF probe.
// The struct layout must exactly match the C struct ssl_data_event_t in kern/nspr_kern.c:
//
//	struct ssl_data_event_t {
//	    enum ssl_data_event_type type;    // u32 at offset 0 (0=read, 1=write)
//	    // implicit 4-byte alignment padding
//	    u64 timestamp_ns;                 // u64 at offset 8
//	    u32 pid;                          // u32 at offset 16
//	    u32 tid;                          // u32 at offset 20
//	    char data[MAX_DATA_SIZE_OPENSSL]; // [16384]byte at offset 24
//	    s32 data_len;                     // s32 at offset 16408
//	    char comm[TASK_COMM_LEN];         // [16]byte at offset 16412
//	};
//	// Total: 16428 bytes
type TLSDataEvent struct {
	// DataType encodes the event type (0=read, 1=write).
	// Uses int64 to absorb the C struct's u32 type + 4-byte alignment padding.
	DataType int64 `json:"dataType"`

	// Timestamp is the event timestamp in nanoseconds
	Timestamp uint64 `json:"timestamp"`

	// PID is the process ID
	PID uint32 `json:"pid"`

	// TID is the thread ID
	TID uint32 `json:"tid"`

	// Data is the TLS data payload
	Data [MaxDataSize]byte `json:"data"`

	// DataLen is the length of actual data
	DataLen int32 `json:"dataLen"`

	// Comm is the process command name
	Comm [TaskCommLen]byte `json:"comm"`
}

// GetTimestamp returns the event timestamp as time.Time
func (e *TLSDataEvent) GetTimestamp() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

// GetPID returns the process ID
func (e *TLSDataEvent) GetPID() uint32 {
	return e.PID
}

// GetTID returns the thread ID
func (e *TLSDataEvent) GetTID() uint32 {
	return e.TID
}

// GetComm returns the process command name
func (e *TLSDataEvent) GetComm() string {
	// Find null terminator
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// GetDataLen returns the length of actual data
func (e *TLSDataEvent) GetDataLen() uint32 {
	return uint32(e.DataLen)
}

// GetData returns the TLS data payload (up to DataLen bytes)
func (e *TLSDataEvent) GetData() []byte {
	if e.DataLen > MaxDataSize {
		return e.Data[:MaxDataSize]
	}
	if e.DataLen < 0 {
		return nil
	}
	return e.Data[:e.DataLen]
}

// IsRead returns true if this is a read event
func (e *TLSDataEvent) IsRead() bool {
	return e.DataType == DataTypeRead
}

// IsWrite returns true if this is a write event
func (e *TLSDataEvent) IsWrite() bool {
	return e.DataType == DataTypeWrite
}

// DecodeFromBytes implements domain.Event interface.
// Reads fields in exact order matching the C struct layout.
func (e *TLSDataEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read DataType (int64 absorbs C's u32 type + 4-byte padding)
	if err := binary.Read(buf, binary.LittleEndian, &e.DataType); err != nil {
		return errors.NewEventDecodeError("nspr.DataType", err)
	}

	// Read Timestamp
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return errors.NewEventDecodeError("nspr.Timestamp", err)
	}

	// Read PID
	if err := binary.Read(buf, binary.LittleEndian, &e.PID); err != nil {
		return errors.NewEventDecodeError("nspr.PID", err)
	}

	// Read TID
	if err := binary.Read(buf, binary.LittleEndian, &e.TID); err != nil {
		return errors.NewEventDecodeError("nspr.TID", err)
	}

	// Read Data
	if err := binary.Read(buf, binary.LittleEndian, &e.Data); err != nil {
		return errors.NewEventDecodeError("nspr.Data", err)
	}

	// Read DataLen
	if err := binary.Read(buf, binary.LittleEndian, &e.DataLen); err != nil {
		return errors.NewEventDecodeError("nspr.DataLen", err)
	}

	// Read Comm
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("nspr.Comm", err)
	}

	return nil
}

// String implements domain.Event interface - returns a human-readable representation
func (e *TLSDataEvent) String() string {
	direction := "read"
	if e.IsWrite() {
		direction = "write"
	}

	return fmt.Sprintf("TLSDataEvent{Timestamp: %v, PID: %d, TID: %d, Comm: %s, Direction: %s, DataLen: %d}",
		e.GetTimestamp(), e.PID, e.TID, e.GetComm(), direction, e.DataLen)
}

// StringHex implements domain.Event interface - returns a hexadecimal representation
func (e *TLSDataEvent) StringHex() string {
	direction := "read"
	if e.IsWrite() {
		direction = "write"
	}

	return fmt.Sprintf("TLSDataEvent{Timestamp: %v, PID: %d, TID: %d, Comm: %s, Direction: %s, DataLen: %d, Data(hex): %x}",
		e.GetTimestamp(), e.PID, e.TID, e.GetComm(), direction, e.DataLen, e.GetData())
}

// Clone implements domain.Event interface
func (e *TLSDataEvent) Clone() domain.Event {
	return &TLSDataEvent{}
}

// Type implements domain.Event interface
func (e *TLSDataEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID implements domain.Event interface
func (e *TLSDataEvent) UUID() string {
	return fmt.Sprintf("%d_%d_%d", e.PID, e.TID, e.Timestamp)
}

// Validate implements domain.Event interface
func (e *TLSDataEvent) Validate() error {
	if e.DataLen > MaxDataSize {
		return fmt.Errorf("invalid data length: %d > %d", e.DataLen, MaxDataSize)
	}
	return nil
}

// Decode is kept for backward compatibility
func (e *TLSDataEvent) Decode(data []byte) error {
	return e.DecodeFromBytes(data)
}

// Encode encodes a TLSDataEvent to binary data
func (e *TLSDataEvent) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write DataType
	if err := binary.Write(buf, binary.LittleEndian, e.DataType); err != nil {
		return nil, fmt.Errorf("failed to write data type: %w", err)
	}

	// Write Timestamp
	if err := binary.Write(buf, binary.LittleEndian, e.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to write timestamp: %w", err)
	}

	// Write PID
	if err := binary.Write(buf, binary.LittleEndian, e.PID); err != nil {
		return nil, fmt.Errorf("failed to write PID: %w", err)
	}

	// Write TID
	if err := binary.Write(buf, binary.LittleEndian, e.TID); err != nil {
		return nil, fmt.Errorf("failed to write TID: %w", err)
	}

	// Write Data
	if err := binary.Write(buf, binary.LittleEndian, e.Data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	// Write DataLen
	if err := binary.Write(buf, binary.LittleEndian, e.DataLen); err != nil {
		return nil, fmt.Errorf("failed to write data length: %w", err)
	}

	// Write Comm
	if err := binary.Write(buf, binary.LittleEndian, e.Comm); err != nil {
		return nil, fmt.Errorf("failed to write comm: %w", err)
	}

	return buf.Bytes(), nil
}
