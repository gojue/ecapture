//go:build windows
// +build windows

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
	"fmt"
	"strings"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// MaxDataSizePostgres is the maximum size of SQL query data captured on Windows.
const MaxDataSizePostgres = 256

// WindowsEvent represents a PostgreSQL query event captured on Windows via hooking.
type WindowsEvent struct {
	Pid       uint32
	Timestamp int64
	Query     string
	Comm      string
	FuncName  string
}

// Type returns the event type identifier.
func (e *WindowsEvent) Type() domain.EventType { return domain.EventTypeOutput }

// UUID returns a unique identifier for this event.
func (e *WindowsEvent) UUID() string {
	return fmt.Sprintf("postgres_%d_%d", e.Pid, e.Timestamp)
}

// Validate validates the event data.
func (e *WindowsEvent) Validate() error {
	if e.Pid == 0 {
		return errors.New(errors.ErrCodeEventValidation, "invalid event: PID is zero")
	}
	return nil
}

// DecodeFromBytes stores raw query bytes.
func (e *WindowsEvent) DecodeFromBytes(data []byte) error {
	e.Query = string(data)
	if len(e.Query) > MaxDataSizePostgres {
		e.Query = e.Query[:MaxDataSizePostgres]
	}
	return nil
}

// String returns a human-readable string representation of the event.
func (e *WindowsEvent) String() string {
	query := e.Query
	if len(query) > 100 {
		query = query[:100] + "..."
	}
	query = strings.TrimSpace(query)
	return fmt.Sprintf("PID=%d Comm=%s Query=%s", e.Pid, e.Comm, query)
}

// StringHex returns a hexadecimal string representation of the query.
func (e *WindowsEvent) StringHex() string { return fmt.Sprintf("%x", []byte(e.Query)) }

// Clone creates a deep copy of the event.
func (e *WindowsEvent) Clone() domain.Event {
	return &WindowsEvent{
		Pid:       e.Pid,
		Timestamp: e.Timestamp,
		Query:     e.Query,
		Comm:      e.Comm,
		FuncName:  e.FuncName,
	}
}

// GetQuery returns the SQL query string.
func (e *WindowsEvent) GetQuery() string { return e.Query }

// GetComm returns the command name.
func (e *WindowsEvent) GetComm() string { return e.Comm }

// GetPid returns the process ID.
func (e *WindowsEvent) GetPid() uint64 { return uint64(e.Pid) }

// GetTimestamp returns the event timestamp.
func (e *WindowsEvent) GetTimestamp() uint64 { return uint64(e.Timestamp) }

// PerfMonoNs implements domain.MonoNsEvent using the nanosecond timestamp.
func (e *WindowsEvent) PerfMonoNs() uint64 { return uint64(e.Timestamp) }

// NewWindowsEvent creates a WindowsEvent from captured hook parameters.
func NewWindowsEvent(pid uint32, comm, query, funcName string) *WindowsEvent {
	return &WindowsEvent{
		Pid:       pid,
		Timestamp: time.Now().UnixNano(),
		Query:     query,
		Comm:      comm,
		FuncName:  funcName,
	}
}
