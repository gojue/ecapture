/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type AttachType int64

const (
	PROBE_ENTRY AttachType = iota
	PROBE_RET
)

const MAX_DATA_SIZE = 1024 * 4
const SA_DATA_LEN = 14

type SSLDataEvent struct {
	module       IModule
	EventType    int64
	Timestamp_ns uint64
	Pid          uint32
	Tid          uint32
	Data         [MAX_DATA_SIZE]byte
	Data_len     int32
	Comm         [16]byte
	Fd           uint32
}

func (this *SSLDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp_ns); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Data_len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Fd); err != nil {
		return
	}

	return nil
}

func (this *SSLDataEvent) StringHex() string {
	addr := this.module.(*MOpenSSLProbe).GetConn(this.Pid, this.Fd)

	var perfix, connInfo string
	switch AttachType(this.EventType) {
	case PROBE_ENTRY:
		connInfo = fmt.Sprintf("%sRecived %d%s bytes from %s%s%s", COLORGREEN, this.Data_len, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORGREEN
	case PROBE_RET:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, this.Data_len, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", this.EventType)
	}

	b := dumpByteSlice(this.Data[:this.Data_len], perfix)
	b.WriteString(COLORRESET)

	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Payload:\n%s", this.Pid, this.Comm, this.Tid, connInfo, b.String())
	return s
}

func (this *SSLDataEvent) String() string {
	addr := this.module.(*MOpenSSLProbe).GetConn(this.Pid, this.Fd)

	var perfix, connInfo string
	switch AttachType(this.EventType) {
	case PROBE_ENTRY:
		connInfo = fmt.Sprintf("%sRecived %d%s bytes from %s%s%s", COLORGREEN, this.Data_len, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORGREEN
	case PROBE_RET:
		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, this.Data_len, COLORRESET, COLORYELLOW, addr, COLORRESET)
		perfix = COLORPURPLE
	default:
		connInfo = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, this.EventType, COLORRESET)
	}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Payload:\n%s%s%s", this.Pid, this.Comm, this.Tid, connInfo, perfix, string(this.Data[:this.Data_len]), COLORRESET)
	return s
}

func (this *SSLDataEvent) SetModule(module IModule) {
	this.module = module
}

func (this *SSLDataEvent) Module() IModule {
	return this.module
}

func (this *SSLDataEvent) Clone() IEventStruct {
	event := new(SSLDataEvent)
	event.module = this.module
	return event
}

//  connect_events map
/*
uint64_t timestamp_ns;
  uint32_t pid;
  uint32_t tid;
  uint32_t fd;
  char sa_data[SA_DATA_LEN];
  char comm[TASK_COMM_LEN];
*/
type ConnDataEvent struct {
	module      IModule
	TimestampNs uint64
	Pid         uint32
	Tid         uint32
	Fd          uint32
	SaData      [SA_DATA_LEN]byte
	Comm        [16]byte
	addr        string
}

func (this *ConnDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.SaData); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(this.SaData[0:2])
	ip := net.IPv4(this.SaData[2], this.SaData[3], this.SaData[4], this.SaData[5])
	this.addr = fmt.Sprintf("%s:%d", ip, port)

	// save event to this.module
	module := this.module.(*MOpenSSLProbe)
	module.AddConn(this.Pid, this.Fd, this.addr)
	return nil
}

func (this *ConnDataEvent) StringHex() string {
	return ""
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s", this.Pid, this.Comm, this.Tid, this.Fd, this.addr)
	return s
}

func (this *ConnDataEvent) String() string {
	return ""
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s ", this.Pid, this.Comm, this.Tid, this.Fd, this.addr)
	return s
}

func (this *ConnDataEvent) SetModule(module IModule) {
	this.module = module
}

func (this *ConnDataEvent) Module() IModule {
	return this.module
}

func (this *ConnDataEvent) Clone() IEventStruct {
	event := new(ConnDataEvent)
	event.module = this.module
	return event
}
