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
    u64 duration;
    char query[MAX_DATA_SIZE];
*/
const MYSQLD57_MAX_DATA_SIZE = 256

type mysqld57Event struct {
	Pid       uint64
	Timestamp uint64
	Duration  uint64
	query     [MYSQLD57_MAX_DATA_SIZE]uint8
}

func (e *mysqld57Event) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Duration); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.query); err != nil {
		return
	}
	return nil
}

func (ei *mysqld57Event) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Line:%s", ei.Pid, unix.ByteSliceToString((ei.query[:]))))
	return s
}

func (ei *mysqld57Event) Clone() IEventStruct {
	return new(mysqld57Event)
}
