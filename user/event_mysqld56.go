/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

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
    u64 alllen;
    u64 len;
    char comm[TASK_COMM_LEN];
*/
const MYSQLD56_MAX_DATA_SIZE = 256

type mysqld56Event struct {
	Pid       uint64
	Timestamp uint64
	query     [MYSQLD56_MAX_DATA_SIZE]uint8
	alllen    uint64
	len       uint64
	comm      [16]uint8
}

func (e *mysqld56Event) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.query); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.alllen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.comm); err != nil {
		return
	}
	return nil
}

func (ei *mysqld56Event) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  Line:%s", ei.Pid, ei.comm, ei.Timestamp, ei.len, ei.alllen, unix.ByteSliceToString((ei.query[:]))))
	return s
}

func (ei *mysqld56Event) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  Line:%s", ei.Pid, ei.comm, ei.Timestamp, ei.len, ei.alllen, unix.ByteSliceToString((ei.query[:]))))
	return s
}
func (ei *mysqld56Event) Clone() IEventStruct {
	return new(mysqld56Event)
}
