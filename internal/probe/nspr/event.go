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
	// MaxDataSize is the maximum size of TLS data payload
	MaxDataSize = 4096
)

// TLSDataEvent represents a TLS data event from NSPR/NSS
type TLSDataEvent struct {
	// Timestamp is the event timestamp in nanoseconds
	Timestamp uint64

	// PID is the process ID
	PID uint32

	// TID is the thread ID
	TID uint32

	// Comm is the process command name
	Comm [16]byte

	// FD is the file descriptor
	FD int32

	// DataLen is the length of actual data
	DataLen uint32

	// Direction: 0 = read, 1 = write
	Direction uint32

	// Data is the TLS data payload
	Data [MaxDataSize]byte
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

// GetFD returns the file descriptor
func (e *TLSDataEvent) GetFD() int32 {
	return e.FD
}

// GetDataLen returns the length of actual data
func (e *TLSDataEvent) GetDataLen() uint32 {
	return e.DataLen
}

// GetDirection returns the data direction (0 = read, 1 = write)
func (e *TLSDataEvent) GetDirection() uint32 {
	return e.Direction
}

// GetData returns the TLS data payload (up to DataLen bytes)
func (e *TLSDataEvent) GetData() []byte {
	if e.DataLen > MaxDataSize {
		return e.Data[:MaxDataSize]
	}
	return e.Data[:e.DataLen]
}

// IsRead returns true if this is a read event
func (e *TLSDataEvent) IsRead() bool {
	return e.Direction == 0
}

// IsWrite returns true if this is a write event
func (e *TLSDataEvent) IsWrite() bool {
	return e.Direction == 1
}

// DecodeFromBytes implements domain.Event interface
func (e *TLSDataEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewReader(data)

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

	// Read Comm
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("nspr.Comm", err)
	}

	// Read FD
	if err := binary.Read(buf, binary.LittleEndian, &e.FD); err != nil {
		return errors.NewEventDecodeError("nspr.FD", err)
	}

	// Read DataLen
	if err := binary.Read(buf, binary.LittleEndian, &e.DataLen); err != nil {
		return errors.NewEventDecodeError("nspr.DataLen", err)
	}

	// Read Direction
	if err := binary.Read(buf, binary.LittleEndian, &e.Direction); err != nil {
		return errors.NewEventDecodeError("nspr.Direction", err)
	}

	// Read Data
	if err := binary.Read(buf, binary.LittleEndian, &e.Data); err != nil {
		return errors.NewEventDecodeError("nspr.Data", err)
	}

	return nil
}

// String implements domain.Event interface - returns a human-readable representation
func (e *TLSDataEvent) String() string {
	direction := "read"
	if e.IsWrite() {
		direction = "write"
	}

	return fmt.Sprintf("TLSDataEvent{Timestamp: %v, PID: %d, TID: %d, Comm: %s, FD: %d, Direction: %s, DataLen: %d}",
		e.GetTimestamp(), e.PID, e.TID, e.GetComm(), e.FD, direction, e.DataLen)
}

// StringHex implements domain.Event interface - returns a hexadecimal representation
func (e *TLSDataEvent) StringHex() string {
	direction := "read"
	if e.IsWrite() {
		direction = "write"
	}

	return fmt.Sprintf("TLSDataEvent{Timestamp: %v, PID: %d, TID: %d, Comm: %s, FD: %d, Direction: %s, DataLen: %d, Data(hex): %x}",
		e.GetTimestamp(), e.PID, e.TID, e.GetComm(), e.FD, direction, e.DataLen, e.GetData())
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

	// Write Comm
	if err := binary.Write(buf, binary.LittleEndian, e.Comm); err != nil {
		return nil, fmt.Errorf("failed to write comm: %w", err)
	}

	// Write FD
	if err := binary.Write(buf, binary.LittleEndian, e.FD); err != nil {
		return nil, fmt.Errorf("failed to write FD: %w", err)
	}

	// Write DataLen
	if err := binary.Write(buf, binary.LittleEndian, e.DataLen); err != nil {
		return nil, fmt.Errorf("failed to write data length: %w", err)
	}

	// Write Direction
	if err := binary.Write(buf, binary.LittleEndian, e.Direction); err != nil {
		return nil, fmt.Errorf("failed to write direction: %w", err)
	}

	// Write Data
	if err := binary.Write(buf, binary.LittleEndian, e.Data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	return buf.Bytes(), nil
}
