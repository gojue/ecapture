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

package openssl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	// Data type constants
	DataTypeRead  = 0
	DataTypeWrite = 1

	// MaxDataSize is the maximum TLS data size from eBPF
	// Increased to 16KB, fix: https://github.com/gojue/ecapture/issues/740
	MaxDataSize   = 1024 * 16
	ChunkSize     = 32
	ChunkSizeHalf = ChunkSize / 2
)

type AttachType int64

const (
	ProbeEntry AttachType = iota
	ProbeRet
)

const (
	Ssl2Version   = 0x0002
	Ssl3Version   = 0x0300
	Tls1Version   = 0x0301
	Tls11Version  = 0x0302
	Tls12Version  = 0x0303
	Tls13Version  = 0x0304
	Dtls1Version  = 0xFEFF
	Dtls12Version = 0xFEFD
)

type TlsVersion struct {
	Version int32
}

func (t TlsVersion) String() string {
	switch t.Version {
	case Ssl2Version:
		return "SSL2_VERSION"
	case Ssl3Version:
		return "SSL3_VERSION"
	case Tls1Version:
		return "TLS1_VERSION"
	case Tls11Version:
		return "TLS1_1_VERSION"
	case Tls12Version:
		return "TLS1_2_VERSION"
	case Tls13Version:
		return "TLS1_3_VERSION"
	case Dtls1Version:
		return "DTLS1_VERSION"
	case Dtls12Version:
		return "DTLS1_2_VERSION"
	}
	return fmt.Sprintf("TLS_VERSION_UNKNOWN_%d", t.Version)
}

/*
struct ssl_data_event_t {
    enum ssl_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char data[MAX_DATA_SIZE_OPENSSL];
    s32 data_len;
    char comm[TASK_COMM_LEN];
    u32 fd;
    s32 version;
    u32 bio_type;
};
*/
// Event represents an OpenSSL TLS data event from eBPF.
type Event struct {
	DataType  int64             `json:"dataType"`
	Timestamp uint64            `json:"timestamp"` // Nanosecond timestamp
	Pid       uint32            `json:"pid"`       // Process ID
	Tid       uint32            `json:"tid"`       // Thread ID
	Data      [MaxDataSize]byte `json:"data"`      // TLS data payload
	DataLen   int32             `json:"dataLen"`   // Length of actual data
	Comm      [TaskCommLen]byte `json:"comm"`      // Process name
	Fd        uint32            `json:"fd"`
	Version   int32             `json:"version"` // TLS version (e.g., 771 for TLS 1.2)
	Tuple     string
	BioType   uint32
	Sock      uint64
}

// DecodeFromBytes deserializes the event from raw eBPF data.
func (e *Event) DecodeFromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.LittleEndian, &e.DataType); err != nil {
		return errors.NewEventDecodeError("openssl.DataType", err)
	}
	// Read fields in order matching the eBPF structure
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return errors.NewEventDecodeError("openssl.Timestamp", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("openssl.Pid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return errors.NewEventDecodeError("openssl.Tid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Data); err != nil {
		return errors.NewEventDecodeError("openssl.Data", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.DataLen); err != nil {
		return errors.NewEventDecodeError("openssl.DataLen", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("openssl.Comm", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Fd); err != nil {
		return errors.NewEventDecodeError("openssl.Fd", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Version); err != nil {
		return errors.NewEventDecodeError("openssl.Version", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.BioType); err != nil {
		return errors.NewEventDecodeError("openssl.BioType", err)
	}

	return nil
}

// String returns a human-readable representation of the event.
func (e *Event) String() string {
	direction := "WRITE"
	if e.DataType == DataTypeRead {
		direction = "READ"
	}

	// 2. 获取时间偏移量
	offsetNs, err := getClockOffset()
	if err != nil {
		panic(err)
	}
	// 3. 计算绝对时间戳（纳秒）
	absoluteTimeNs := int64(e.Timestamp) + offsetNs

	// 4. 将纳秒转换为 Go 的 time.Time 对象
	// time.Unix(sec, nsec)
	eventTime := time.Unix(0, absoluteTimeNs)

	dataStr := string(e.GetData())

	return fmt.Sprintf("[%s] PID:%d TID:%d Comm:%s FD:%d %s (%d bytes):\n%s",
		eventTime.Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		e.GetComm(),
		e.Fd,
		direction,
		e.DataLen,
		dataStr,
	)
}

// StringHex returns a hexadecimal representation of the event.
func (e *Event) StringHex() string {
	direction := "WRITE"
	if e.DataType == DataTypeRead {
		direction = "READ"
	}

	ts := time.Unix(int64(e.Timestamp), 0)

	hexData := dumpByteSlice(e.GetData(), "")

	return fmt.Sprintf("[%s] PID:%d TID:%d Comm:%s FD:%d %s (%d bytes, hex):\n%s",
		ts.Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		e.GetComm(),
		e.Fd,
		direction,
		e.DataLen,
		hexData,
	)
}

func (e *Event) BaseInfo() string {
	addr := "[TODO]"
	if e.Tuple != "" {
		addr = e.Tuple
	}
	var connInfo string
	switch AttachType(e.DataType) {
	case ProbeEntry:
		connInfo = fmt.Sprintf("Received %d bytes from %s", e.DataLen, addr)
	case ProbeRet:
		connInfo = fmt.Sprintf("Send %d bytes to %s", e.DataLen, addr)
	default:
		connInfo = fmt.Sprintf("UNKNOWN_%d", e.DataType)
	}
	v := TlsVersion{Version: e.Version}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, Version:%s, %s", e.Pid, commStr(e.Comm[:]), e.Tid, v.String(), connInfo)
	return s
}

// Clone creates a new instance of the event.
func (e *Event) Clone() domain.Event {
	clone := *e
	return &clone
}

// Type returns the event type (always Output for TLS data).
func (e *Event) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event.
func (e *Event) UUID() string {
	return fmt.Sprintf("%d_%d_%d", e.Pid, e.Tid, e.Timestamp)
}

// Validate checks if the event data is valid.
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

// GetPid returns the process ID.
func (e *Event) GetPid() uint32 {
	return e.Pid
}

// GetComm returns the process name as a string.
func (e *Event) GetComm() string {
	return commToString(e.Comm[:])
}

// GetData returns the actual TLS data (truncated to DataLen).
func (e *Event) GetData() []byte {
	if e.DataLen <= 0 {
		return []byte{}
	}
	if e.DataLen > MaxDataSize {
		return e.Data[:]
	}
	return e.Data[:e.DataLen]
}

// GetDataLen returns the length of the TLS data.
func (e *Event) GetDataLen() uint32 {
	if e.DataLen < 0 {
		return 0
	}
	return uint32(e.DataLen)
}

// GetTimestamp returns the event timestamp.
func (e *Event) GetTimestamp() uint64 {
	return e.Timestamp
}

// IsRead returns true if this is a read (receive) event.
func (e *Event) IsRead() bool {
	return e.DataType == DataTypeRead
}

// commToString converts a null-terminated byte array to a string.
func commToString(data []byte) string {
	// Find null terminator
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

//// Decode implements domain.EventDecoder interface for TLS data events.
//func (e *Event) Decode(data []byte) (domain.Event, error) {
//	event := &Event{}
//	if err := event.DecodeFromBytes(data); err != nil {
//		return nil, err
//	}
//	if err := event.Validate(); err != nil {
//		return nil, err
//	}
//	return event, nil
//}

func dumpByteSlice(b []byte, prefix string) *bytes.Buffer {
	var a [ChunkSize]byte
	bb := new(bytes.Buffer)
	n := (len(b) + (ChunkSize - 1)) &^ (ChunkSize - 1)

	for i := 0; i < n; i++ {

		// 序号列
		if i%ChunkSize == 0 {
			bb.WriteString(prefix)
			_, _ = fmt.Fprintf(bb, "%04X", i)
		}

		// 长度的一半，则输出4个空格
		if i%ChunkSizeHalf == 0 {
			bb.WriteString("  ")
		} else if i%(ChunkSizeHalf/2) == 0 {
			bb.WriteString(" ")
		}

		if i < len(b) {
			_, _ = fmt.Fprintf(bb, "%02X", b[i])
		} else {
			bb.WriteString(" ")
		}

		// 非ASCII 改为 .
		if i >= len(b) {
			a[i%ChunkSize] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%ChunkSize] = '.'
		} else {
			a[i%ChunkSize] = b[i]
		}

		// 如果到达size长度，则换行
		if i%ChunkSize == (ChunkSize - 1) {
			_, _ = fmt.Fprintf(bb, "    %s\n", string(a[:]))
		}
	}
	return bb
}

// getClockOffset 计算 CLOCK_REALTIME (绝对时间) 和 CLOCK_MONOTONIC (单调时间) 之间的差值。
// 这个差值实际上就是系统的启动时间 (Boot Time)。
func getClockOffset() (int64, error) {
	var tsReal, tsMono unix.Timespec

	// 获取当前墙上时间 (绝对时间)
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &tsReal); err != nil {
		return 0, fmt.Errorf("failed to get CLOCK_REALTIME: %w", err)
	}

	// 获取当前单调时间 (自启动以来的时间)
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &tsMono); err != nil {
		return 0, fmt.Errorf("failed to get CLOCK_MONOTONIC: %w", err)
	}

	// 转换为纳秒并计算差值
	realNs := tsReal.Sec*1e9 + tsReal.Nsec
	monoNs := tsMono.Sec*1e9 + tsMono.Nsec

	return realNs - monoNs, nil
}
