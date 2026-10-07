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

package gnutls

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
)

const (
	DataTypeRead  = 0
	DataTypeWrite = 1

	// MaxDataSize and TaskCommLen must match MAX_DATA_SIZE_OPENSSL and
	// TASK_COMM_LEN in kern/common.h.
	MaxDataSize = 1024 * 16
	TaskCommLen = 16

	tlsDataEventSize = 8 + 8 + 4 + 4 + MaxDataSize + 4 + TaskCommLen
)

// Event mirrors struct ssl_data_event_t in kern/gnutls.h. DataType is int64
// so its upper four bytes absorb the alignment padding between the C enum and
// timestamp_ns.
type Event struct {
	DataType  int64             `json:"dataType"`
	Timestamp uint64            `json:"timestamp"`
	Pid       uint32            `json:"pid"`
	Tid       uint32            `json:"tid"`
	Data      [MaxDataSize]byte `json:"data"`
	DataLen   int32             `json:"dataLen"`
	Comm      [TaskCommLen]byte `json:"comm"`
}

func (e *Event) DecodeFromBytes(data []byte) error {
	if len(data) < tlsDataEventSize {
		return errors.New(errors.ErrCodeEventDecode,
			fmt.Sprintf("gnutls data event too short: got %d, need %d", len(data), tlsDataEventSize))
	}

	buf := bytes.NewReader(data)
	fields := []struct {
		name  string
		value any
	}{
		{"DataType", &e.DataType},
		{"Timestamp", &e.Timestamp},
		{"Pid", &e.Pid},
		{"Tid", &e.Tid},
		{"Data", &e.Data},
		{"DataLen", &e.DataLen},
		{"Comm", &e.Comm},
	}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field.value); err != nil {
			return errors.NewEventDecodeError("gnutls."+field.name, err)
		}
	}
	return nil
}

// PerfMonoNs implements domain.MonoNsEvent using bpf_ktime_get_ns from the
// wire event.
func (e *Event) PerfMonoNs() uint64 {
	return e.Timestamp
}

func (e *Event) String() string {
	direction := "WRITE"
	if e.DataType == DataTypeRead {
		direction = "READ"
	}
	return fmt.Sprintf("[mono_ns=%d] PID:%d TID:%d Comm:%s %s (%d bytes):\n%s",
		e.Timestamp, e.Pid, e.Tid, e.GetComm(), direction, e.DataLen, string(e.GetData()))
}

func (e *Event) StringHex() string {
	direction := "WRITE"
	if e.DataType == DataTypeRead {
		direction = "READ"
	}
	return fmt.Sprintf("[mono_ns=%d] PID:%d TID:%d Comm:%s %s (%d bytes, hex):\n%x",
		e.Timestamp, e.Pid, e.Tid, e.GetComm(), direction, e.DataLen, e.GetData())
}

func (e *Event) Clone() domain.Event {
	clone := *e
	return &clone
}

func (e *Event) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (e *Event) UUID() string {
	return fmt.Sprintf("%d_%d_%d", e.Pid, e.Tid, e.Timestamp)
}

func (e *Event) Validate() error {
	if e.DataLen < 0 || e.DataLen > MaxDataSize {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid data length: %d", e.DataLen))
	}
	if e.DataType != DataTypeRead && e.DataType != DataTypeWrite {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid data type: %d", e.DataType))
	}
	return nil
}

func (e *Event) GetPid() uint32 {
	return e.Pid
}

func (e *Event) GetComm() string {
	return commToString(e.Comm[:])
}

func (e *Event) GetData() []byte {
	if e.DataLen <= 0 {
		return nil
	}
	if e.DataLen > MaxDataSize {
		return e.Data[:]
	}
	return e.Data[:e.DataLen]
}

func (e *Event) GetDataLen() uint32 {
	if e.DataLen < 0 {
		return 0
	}
	return uint32(e.DataLen)
}

func (e *Event) GetTimestamp() uint64 {
	return e.Timestamp
}

func (e *Event) IsRead() bool {
	return e.DataType == DataTypeRead
}

func commToString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
