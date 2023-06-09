//go:build !androidgki
// +build !androidgki

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

package event

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

/*
u64 pid;
u64 timestamp;
char Query[MAX_DATA_SIZE];
char Comm[TASK_COMM_LEN];
*/
const PostgresMaxDataSize = 256

type PostgresEvent struct {
	eventType EventType
	Pid       uint64                     `json:"pid"`
	Timestamp uint64                     `json:"timestamp"`
	Query     [PostgresMaxDataSize]uint8 `json:"Query"`
	Comm      [16]uint8                  `json:"Comm"`
}

func (pe *PostgresEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &pe.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &pe.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &pe.Query); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &pe.Comm); err != nil {
		return
	}
	return nil
}

func (pe *PostgresEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID: %d, Comm: %s, Time: %d, Query: %s", pe.Pid, pe.Comm, pe.Timestamp, unix.ByteSliceToString((pe.Query[:]))))
	return s
}

func (pe *PostgresEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID: %d, Comm: %s, Time: %d, Query: %s", pe.Pid, pe.Comm, pe.Timestamp, unix.ByteSliceToString((pe.Query[:]))))
	return s
}

func (pe *PostgresEvent) Clone() IEventStruct {
	event := new(PostgresEvent)
	event.eventType = EventTypeOutput
	return event
}

func (pe *PostgresEvent) EventType() EventType {
	return pe.eventType
}

func (pe *PostgresEvent) GetUUID() string {
	return fmt.Sprintf("%d_%s", pe.Pid, pe.Comm)
}

func (pe *PostgresEvent) Payload() []byte {
	return pe.Query[:]
}

func (pe *PostgresEvent) PayloadLen() int {
	return len(pe.Query)
}
