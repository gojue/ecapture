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
)

// TLSDataEvent represents a TLS data read/write event from GoTLS
// This structure matches the eBPF event structure
type TLSDataEvent struct {
	Timestamp uint64     // Timestamp in nanoseconds
	Pid       uint32     // Process ID
	Tid       uint32     // Thread ID
	DataLen   uint32     // Length of actual data
	Direction uint32     // 0 = read, 1 = write
	Data      [4096]byte // TLS data buffer (max 4KB per event)
}

// Decode decodes the binary event data
func (e *TLSDataEvent) Decode(data []byte) error {
	if len(data) < 24 { // Minimum size: 8+4+4+4+4
		return fmt.Errorf("data too short: got %d bytes, need at least 24", len(data))
	}

	buf := bytes.NewReader(data)

	// Read timestamp
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return fmt.Errorf("failed to read timestamp: %w", err)
	}

	// Read PID
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return fmt.Errorf("failed to read PID: %w", err)
	}

	// Read TID
	if err := binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return fmt.Errorf("failed to read TID: %w", err)
	}

	// Read data length
	if err := binary.Read(buf, binary.LittleEndian, &e.DataLen); err != nil {
		return fmt.Errorf("failed to read data length: %w", err)
	}

	// Read direction
	if err := binary.Read(buf, binary.LittleEndian, &e.Direction); err != nil {
		return fmt.Errorf("failed to read direction: %w", err)
	}

	// Read data
	if e.DataLen > 4096 {
		return fmt.Errorf("data length too large: %d (max 4096)", e.DataLen)
	}

	remaining := len(data) - 24
	if remaining > 0 {
		if remaining > 4096 {
			remaining = 4096
		}
		copy(e.Data[:], data[24:24+remaining])
	}

	return nil
}

// Encode encodes the event to binary format
func (e *TLSDataEvent) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write timestamp
	if err := binary.Write(buf, binary.LittleEndian, e.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to write timestamp: %w", err)
	}

	// Write PID
	if err := binary.Write(buf, binary.LittleEndian, e.Pid); err != nil {
		return nil, fmt.Errorf("failed to write PID: %w", err)
	}

	// Write TID
	if err := binary.Write(buf, binary.LittleEndian, e.Tid); err != nil {
		return nil, fmt.Errorf("failed to write TID: %w", err)
	}

	// Write data length
	if err := binary.Write(buf, binary.LittleEndian, e.DataLen); err != nil {
		return nil, fmt.Errorf("failed to write data length: %w", err)
	}

	// Write direction
	if err := binary.Write(buf, binary.LittleEndian, e.Direction); err != nil {
		return nil, fmt.Errorf("failed to write direction: %w", err)
	}

	// Write data
	dataLen := e.DataLen
	if dataLen > 4096 {
		dataLen = 4096
	}
	if _, err := buf.Write(e.Data[:dataLen]); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	return buf.Bytes(), nil
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
	return e.Direction == 0
}

// IsWrite returns true if this is a write event
func (e *TLSDataEvent) IsWrite() bool {
	return e.Direction == 1
}

// String returns a string representation of the event
func (e *TLSDataEvent) String() string {
	direction := "read"
	if e.IsWrite() {
		direction = "write"
	}

	return fmt.Sprintf("TLSDataEvent{ts=%s, pid=%d, tid=%d, dir=%s, len=%d}",
		e.GetTimestamp().Format(time.RFC3339Nano),
		e.Pid,
		e.Tid,
		direction,
		e.DataLen)
}
