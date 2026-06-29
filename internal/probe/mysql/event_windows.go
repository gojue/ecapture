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

package mysql

import (
	"fmt"
	"strings"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// MaxDataSize is the maximum size of query data captured on Windows.
const MaxDataSize = 256

// WindowsEvent represents a MySQL query event captured on Windows via hooking.
type WindowsEvent struct {
	Pid       uint32
	Timestamp int64
	Query     string
	AllLen    uint32
	Len       uint32
	Comm      string
	FuncName  string
}

// DecodeFromBytes stores raw query bytes.
func (e *WindowsEvent) DecodeFromBytes(data []byte) error {
	e.Query = string(data)
	if len(e.Query) > MaxDataSize {
		e.Query = e.Query[:MaxDataSize]
	}
	return nil
}

// Type returns the event type identifier.
func (e *WindowsEvent) Type() domain.EventType { return domain.EventTypeOutput }

// UUID returns a unique identifier for the event.
func (e *WindowsEvent) UUID() string {
	return fmt.Sprintf("mysql_%d_%d", e.Pid, e.Timestamp)
}

// Validate validates the event data.
func (e *WindowsEvent) Validate() error {
	if e.Pid == 0 {
		return errors.New(errors.ErrCodeEventValidation, "invalid event: PID is zero")
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
	return fmt.Sprintf("MySQL Query[PID=%d, Comm=%s, Len=%d/%d]: %s",
		e.Pid, e.Comm, e.Len, e.AllLen, query)
}

// StringHex returns a hexadecimal representation of the query.
func (e *WindowsEvent) StringHex() string { return fmt.Sprintf("%x", []byte(e.Query)) }

// Clone creates a deep copy of the event.
func (e *WindowsEvent) Clone() domain.Event {
	return &WindowsEvent{
		Pid:       e.Pid,
		Timestamp: e.Timestamp,
		Query:     e.Query,
		AllLen:    e.AllLen,
		Len:       e.Len,
		Comm:      e.Comm,
		FuncName:  e.FuncName,
	}
}

// GetPID returns the process ID.
func (e *WindowsEvent) GetPID() uint32 { return e.Pid }

// GetComm returns the command name.
func (e *WindowsEvent) GetComm() string { return e.Comm }

// GetQuery returns the SQL query string.
func (e *WindowsEvent) GetQuery() string { return e.Query }

// GetQueryLen returns the length of the captured query.
func (e *WindowsEvent) GetQueryLen() uint32 { return e.Len }

// GetTotalQueryLen returns the total length of the query.
func (e *WindowsEvent) GetTotalQueryLen() uint32 { return e.AllLen }

// IsTruncated returns true if the query was truncated.
func (e *WindowsEvent) IsTruncated() bool { return e.Len < e.AllLen }

// PerfMonoNs implements domain.MonoNsEvent using the nanosecond timestamp.
func (e *WindowsEvent) PerfMonoNs() uint64 {
	return uint64(e.Timestamp)
}

// NewWindowsEvent creates a WindowsEvent from captured hook parameters.
func NewWindowsEvent(pid uint32, comm, query, funcName string) *WindowsEvent {
	now := time.Now().UnixNano()
	return &WindowsEvent{
		Pid:       pid,
		Timestamp: now,
		Query:     query,
		AllLen:    uint32(len(query)),
		Len:       uint32(len(query)),
		Comm:      comm,
		FuncName:  funcName,
	}
}
