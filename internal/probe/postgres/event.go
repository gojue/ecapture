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

package postgres

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	// MaxDataSizePostgres is the maximum size of SQL query data captured
	MaxDataSizePostgres = 256
)

// Event represents a PostgreSQL query event from eBPF
// This structure matches the C struct in postgres_kern.c:
//
//	struct postgres_event_t {
//	    u64 pid;
//	    u64 timestamp;
//	    char Query[MAX_DATA_SIZE];
//	    char Comm[TASK_COMM_LEN];
//	};
type Event struct {
	Pid       uint64                     `json:"pid"`
	Timestamp uint64                     `json:"timestamp"`
	Query     [MaxDataSizePostgres]uint8 `json:"query"`
	Comm      [16]uint8                  `json:"comm"`
}

// Type returns the event type identifier
func (e *Event) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event
func (e *Event) UUID() string {
	return fmt.Sprintf("postgres_%d_%d", e.Pid, e.Timestamp)
}

// Validate validates the event data
func (e *Event) Validate() error {
	if e.Pid == 0 {
		return errors.New(errors.ErrCodeEventValidation, "invalid event: PID is zero")
	}
	if e.Timestamp == 0 {
		return errors.New(errors.ErrCodeEventValidation, "invalid event: timestamp is zero")
	}
	return nil
}

// DecodeFromBytes decodes the event from raw bytes
func (e *Event) DecodeFromBytes(data []byte) error {
	if len(data) < binary.Size(e) {
		return errors.New(errors.ErrCodeEventDecode, "insufficient data for PostgreSQL event").
			WithContext("expected", binary.Size(e)).
			WithContext("actual", len(data))
	}

	buf := bytes.NewReader(data)

	// Read PID
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.Wrap(errors.ErrCodeEventDecode, "failed to decode PID", err)
	}

	// Read Timestamp
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return errors.Wrap(errors.ErrCodeEventDecode, "failed to decode timestamp", err)
	}

	// Read Query
	if err := binary.Read(buf, binary.LittleEndian, &e.Query); err != nil {
		return errors.Wrap(errors.ErrCodeEventDecode, "failed to decode query", err)
	}

	// Read Comm
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.Wrap(errors.ErrCodeEventDecode, "failed to decode comm", err)
	}

	return nil
}

// String returns a human-readable string representation of the event
func (e *Event) String() string {
	query := unix.ByteSliceToString(e.Query[:])
	comm := unix.ByteSliceToString(e.Comm[:])

	// Truncate long queries for display
	if len(query) > 100 {
		query = query[:100] + "..."
	}

	return fmt.Sprintf("PID=%d Comm=%s Query=%s",
		e.Pid, comm, query)
}

// StringHex returns a hexadecimal string representation of the event
func (e *Event) StringHex() string {
	return fmt.Sprintf("PID=0x%x Timestamp=0x%x Query=%x Comm=%x",
		e.Pid, e.Timestamp, e.Query[:32], e.Comm)
}

// Clone creates a deep copy of the event
func (e *Event) Clone() domain.Event {
	clone := &Event{
		Pid:       e.Pid,
		Timestamp: e.Timestamp,
	}
	copy(clone.Query[:], e.Query[:])
	copy(clone.Comm[:], e.Comm[:])
	return clone
}

// GetQuery returns the SQL query string
func (e *Event) GetQuery() string {
	return unix.ByteSliceToString(e.Query[:])
}

// GetComm returns the command name
func (e *Event) GetComm() string {
	return unix.ByteSliceToString(e.Comm[:])
}

// GetPid returns the process ID
func (e *Event) GetPid() uint64 {
	return e.Pid
}

// GetTimestamp returns the event timestamp
func (e *Event) GetTimestamp() uint64 {
	return e.Timestamp
}

// IsTruncated checks if the query was truncated
func (e *Event) IsTruncated() bool {
	// Check if the query fills the entire buffer
	for i := MaxDataSizePostgres - 1; i >= 0; i-- {
		if e.Query[i] != 0 {
			// Found non-zero byte at the end, query might be truncated
			return i == MaxDataSizePostgres-1
		}
	}
	return false
}
