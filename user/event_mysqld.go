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
const MYSQLD_MAX_DATA_SIZE = 256

const (
	//dispatch_command_return
	DISPATCH_COMMAND_V57_FAILED       = -2
	DISPATCH_COMMAND_NOT_CAPTURED     = -1
	DISPATCH_COMMAND_SUCCESS          = 0
	DISPATCH_COMMAND_CLOSE_CONNECTION = 1
	DISPATCH_COMMAND_WOULDBLOCK       = 2
)

type dispatch_command_return int8

func (this dispatch_command_return) String() string {
	var retStr string
	switch this {
	case DISPATCH_COMMAND_CLOSE_CONNECTION:
		retStr = "DISPATCH_COMMAND_CLOSE_CONNECTION"
	case DISPATCH_COMMAND_SUCCESS:
		retStr = "DISPATCH_COMMAND_SUCCESS"
	case DISPATCH_COMMAND_WOULDBLOCK:
		retStr = "DISPATCH_COMMAND_WOULDBLOCK"
	case DISPATCH_COMMAND_NOT_CAPTURED:
		retStr = "DISPATCH_COMMAND_NOT_CAPTURED"
	case DISPATCH_COMMAND_V57_FAILED:
		retStr = "DISPATCH_COMMAND_V57_FAILED"
	}
	return retStr
}

type mysqldEvent struct {
	module    IModule
	Pid       uint64
	Timestamp uint64
	query     [MYSQLD_MAX_DATA_SIZE]uint8
	alllen    uint64
	len       uint64
	comm      [16]uint8
	retval    dispatch_command_return
}

func (this *mysqldEvent) Decode(payload []byte) (err error) {
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
	if err = binary.Read(buf, binary.LittleEndian, &this.alllen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.retval); err != nil {
		return
	}
	return nil
}

func (this *mysqldEvent) String() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  return:%s, Line:%s", this.Pid, this.comm, this.Timestamp, this.len, this.alllen, this.retval, unix.ByteSliceToString((this.query[:]))))
	return s
}

func (this *mysqldEvent) StringHex() string {
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, Comm:%s, Time:%d,  length:(%d/%d),  return:%s, Line:%s", this.Pid, this.comm, this.Timestamp, this.len, this.alllen, this.retval, unix.ByteSliceToString((this.query[:]))))
	return s
}

func (this *mysqldEvent) SetModule(module IModule) {
	this.module = module
}

func (this *mysqldEvent) Module() IModule {
	return this.module
}

func (this *mysqldEvent) Clone() IEventStruct {
	return new(mysqldEvent)
}
