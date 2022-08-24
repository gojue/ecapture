package event_processor

import (
	"bytes"
	"ecapture/user/event"
	"encoding/binary"
	"fmt"
)

type AttachType int64

const (
	PROBE_ENTRY AttachType = iota
	PROBE_RET
)

// 格式化输出相关

const CHUNK_SIZE = 16
const CHUNK_SIZE_HALF = CHUNK_SIZE / 2

const MAX_DATA_SIZE = 1024 * 4
const SA_DATA_LEN = 14

const (
	SSL2_VERSION    = 0x0002
	SSL3_VERSION    = 0x0300
	TLS1_VERSION    = 0x0301
	TLS1_1_VERSION  = 0x0302
	TLS1_2_VERSION  = 0x0303
	TLS1_3_VERSION  = 0x0304
	DTLS1_VERSION   = 0xFEFF
	DTLS1_2_VERSION = 0xFEFD
)

type tls_version struct {
	version int32
}

func (t tls_version) String() string {
	switch t.version {
	case SSL2_VERSION:
		return "SSL2_VERSION"
	case SSL3_VERSION:
		return "SSL3_VERSION"
	case TLS1_VERSION:
		return "TLS1_VERSION"
	case TLS1_1_VERSION:
		return "TLS1_1_VERSION"
	case TLS1_2_VERSION:
		return "TLS1_2_VERSION"
	case TLS1_3_VERSION:
		return "TLS1_3_VERSION"
	case DTLS1_VERSION:
		return "DTLS1_VERSION"
	case DTLS1_2_VERSION:
		return "DTLS1_2_VERSION"
	}
	return fmt.Sprintf("TLS_VERSION_UNKNOW_%d", t.version)
}

type BaseEvent struct {
	event_type   event.EventType
	DataType     int64
	Timestamp_ns uint64
	Pid          uint32
	Tid          uint32
	Data         [MAX_DATA_SIZE]byte
	Data_len     int32
	Comm         [16]byte
	Fd           uint32
	Version      int32
}

func (this *BaseEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.DataType); err != nil {
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
	if err = binary.Read(buf, binary.LittleEndian, &this.Version); err != nil {
		return
	}

	return nil
}

func (this *BaseEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", this.Pid, this.Tid, CToGoString(this.Comm[:]), this.Fd, this.DataType)
}

func (this *BaseEvent) Payload() []byte {
	return this.Data[:this.Data_len]
}

func (this *BaseEvent) PayloadLen() int {
	return int(this.Data_len)
}

func (this *BaseEvent) StringHex() string {

	var perfix, connInfo string
	switch AttachType(this.DataType) {
	case PROBE_ENTRY:
		connInfo = fmt.Sprintf("Recived %d bytes", this.Data_len)
	case PROBE_RET:
		connInfo = fmt.Sprintf("Send %d bytes", this.Data_len)
	default:
		perfix = fmt.Sprintf("UNKNOW_%d", this.DataType)
	}

	b := dumpByteSlice(this.Data[:this.Data_len], perfix)

	v := tls_version{version: this.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Payload:\n%s", this.Pid, CToGoString(this.Comm[:]), this.Tid, connInfo, v.String(), b.String())
	return s
}

func (this *BaseEvent) String() string {

	var connInfo string
	switch AttachType(this.DataType) {
	case PROBE_ENTRY:
		connInfo = fmt.Sprintf("Recived %dbytes", this.Data_len)
	case PROBE_RET:
		connInfo = fmt.Sprintf("Send %d bytes", this.Data_len)
	default:
		connInfo = fmt.Sprintf("UNKNOW_%d", this.DataType)
	}
	v := tls_version{version: this.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, Version:%s, %s, Payload:\n%s", this.Pid, bytes.TrimSpace(this.Comm[:]), this.Tid, v.String(), connInfo, string(this.Data[:this.Data_len]))
	return s
}

func (this *BaseEvent) Clone() event.IEventStruct {
	e := new(BaseEvent)
	e.event_type = event.EventTypeOutput
	return e
}

func (this *BaseEvent) EventType() event.EventType {
	return this.event_type
}

func CToGoString(c []byte) string {
	n := -1
	for i, b := range c {
		if b == 0 {
			break
		}
		n = i
	}
	return string(c[:n+1])
}

func dumpByteSlice(b []byte, perfix string) *bytes.Buffer {
	var a [CHUNK_SIZE]byte
	bb := new(bytes.Buffer)
	n := (len(b) + (CHUNK_SIZE - 1)) &^ (CHUNK_SIZE - 1)

	for i := 0; i < n; i++ {

		// 序号列
		if i%CHUNK_SIZE == 0 {
			bb.WriteString(perfix)
			bb.WriteString(fmt.Sprintf("%04d", i))
		}

		// 长度的一半，则输出4个空格
		if i%CHUNK_SIZE_HALF == 0 {
			bb.WriteString("    ")
		} else if i%(CHUNK_SIZE_HALF/2) == 0 {
			bb.WriteString("  ")
		}

		if i < len(b) {
			bb.WriteString(fmt.Sprintf(" %02X", b[i]))
		} else {
			bb.WriteString("  ")
		}

		// 非ASCII 改为 .
		if i >= len(b) {
			a[i%CHUNK_SIZE] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%CHUNK_SIZE] = '.'
		} else {
			a[i%CHUNK_SIZE] = b[i]
		}

		// 如果到达size长度，则换行
		if i%CHUNK_SIZE == (CHUNK_SIZE - 1) {
			bb.WriteString(fmt.Sprintf("    %s\n", string(a[:])))
		}
	}
	return bb
}
