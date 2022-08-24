//go:build !androidgki
// +build !androidgki

/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
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
   char query[MAX_DATA_SIZE];
   char comm[TASK_COMM_LEN];
*/
const POSTGRES_MAX_DATA_SIZE = 256

type PostgresEvent struct {
	event_type EventType
	Pid        uint64
	Timestamp  uint64
	query      [POSTGRES_MAX_DATA_SIZE]uint8
	comm       [16]uint8
}

func (this *PostgresEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.query); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.comm); err != nil {
		return
	}
	return nil
}

func (this *PostgresEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID: %d, Comm: %s, Time: %d, Query: %s", this.Pid, this.comm, this.Timestamp, unix.ByteSliceToString((this.query[:]))))
	return s
}

func (this *PostgresEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID: %d, Comm: %s, Time: %d, Query: %s", this.Pid, this.comm, this.Timestamp, unix.ByteSliceToString((this.query[:]))))
	return s
}

func (this *PostgresEvent) Clone() IEventStruct {
	event := new(PostgresEvent)
	event.event_type = EventTypeOutput
	return event
}

func (this *PostgresEvent) EventType() EventType {
	return this.event_type
}

func (this *PostgresEvent) GetUUID() string {
	return fmt.Sprintf("%d_%s", this.Pid, this.comm)
}

func (this *PostgresEvent) Payload() []byte {
	return this.query[:]
}

func (this *PostgresEvent) PayloadLen() int {
	return len(this.query)
}
