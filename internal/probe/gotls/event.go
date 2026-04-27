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

package gotls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	maxGoTLSPayload = 16 * 1024
	DefaultTuple    = "0.0.0.0:0-0.0.0.0:0"
)

// GoTLSDataEvent represents a TLS data read/write event from GoTLS
// This structure matches the eBPF event structure: struct go_tls_event
//
// C struct layout (go_tls_event):
//
//	u64 ts_ns;           // offset 0,  size 8
//	u32 pid;             // offset 8,  size 4
//	u32 tid;             // offset 12, size 4
//	s32 data_len;        // offset 16, size 4
//	u8  event_type;      // offset 20, size 1
//	u8  pad[3];          // offset 21, size 3 (alignment padding)
//	u32 fd;              // offset 24, size 4
//	u8  src_ip[16];      // offset 28, size 16
//	u16 src_port;        // offset 44, size 2
//	u16 pad2;            // offset 46, size 2 (alignment padding)
//	u8  dst_ip[16];      // offset 48, size 16
//	u16 dst_port;        // offset 64, size 2
//	u8  ip_version;      // offset 66, size 1 (4=IPv4, 6=IPv6)
//	u8  pad3;            // offset 67, size 1 (alignment padding)
//	char comm[16];       // offset 68, size 16
//	char data[...];      // offset 84, variable
type GoTLSDataEvent struct {
	Timestamp uint64 `json:"timestamp"`
	// BpfMonoNs is bpf_ktime_get_ns from the wire (same as Timestamp until zero fallback replaces display time).
	BpfMonoNs uint64 `json:"-"`
	Pid       uint32 `json:"pid"`
	Tid       uint32 `json:"tid"`
	DataLen   int32  `json:"dataLen"`
	EventType uint8  `json:"eventType"` // 0=WRITE, 1=READ
	pad       [3]byte
	Fd        uint32   `json:"fd"`
	SrcIP     [16]byte `json:"srcIP"`
	SrcPort   uint16   `json:"srcPort"`
	pad2      [2]byte
	DstIP     [16]byte `json:"dstIP"`
	DstPort   uint16   `json:"dstPort"`
	IPVersion uint8    `json:"ipVersion"` // 4=IPv4, 6=IPv6
	pad3      uint8
	Comm      [16]byte `json:"comm"`
	Data      []byte   `json:"data"`
	Tuple     string   `json:"tuple"`
}

// DecodeFromBytes deserializes the event from raw eBPF data.
func (e *GoTLSDataEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read fields in order matching the eBPF structure
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return errors.NewEventDecodeError("gotls.Timestamp", err)
	}
	e.BpfMonoNs = e.Timestamp
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("gotls.Pid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return errors.NewEventDecodeError("gotls.Tid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.DataLen); err != nil {
		return errors.NewEventDecodeError("gotls.DataLen", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.EventType); err != nil {
		return errors.NewEventDecodeError("gotls.EventType", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.pad); err != nil {
		return errors.NewEventDecodeError("gotls.pad", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Fd); err != nil {
		return errors.NewEventDecodeError("gotls.Fd", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.SrcIP); err != nil {
		return errors.NewEventDecodeError("gotls.SrcIP", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.SrcPort); err != nil {
		return errors.NewEventDecodeError("gotls.SrcPort", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.pad2); err != nil {
		return errors.NewEventDecodeError("gotls.pad2", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.DstIP); err != nil {
		return errors.NewEventDecodeError("gotls.DstIP", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.DstPort); err != nil {
		return errors.NewEventDecodeError("gotls.DstPort", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.IPVersion); err != nil {
		return errors.NewEventDecodeError("gotls.IPVersion", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.pad3); err != nil {
		return errors.NewEventDecodeError("gotls.pad3", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("gotls.Comm", err)
	}

	if e.DataLen > 0 {
		remaining := buf.Len()
		if uint64(remaining) < uint64(e.DataLen) {
			return errors.NewEventDecodeError("gotls.DataLen", fmt.Errorf("data length %d exceeds remaining buffer %d", e.DataLen, remaining))
		}
		if uint64(e.DataLen) > uint64(maxGoTLSPayload) {
			return errors.NewEventDecodeError("gotls.DataLen", fmt.Errorf("data length %d exceeds maximum allowed %d", e.DataLen, maxGoTLSPayload))
		}

		e.Data = make([]byte, int(e.DataLen))
		if err := binary.Read(buf, binary.LittleEndian, &e.Data); err != nil {
			return errors.NewEventDecodeError("gotls.Data", err)
		}
	} else {
		e.DataLen = 0
		e.Data = nil
	}

	if e.Timestamp == 0 {
		e.Timestamp = uint64(time.Now().UnixNano())
	}

	e.GetTuple()

	return nil
}

// LessGoTLSDataEventByPerfOrder compares two events for emit order after merging per-CPU perf buffers.
// Ordering uses only bpf monotonic time (ts_ns on the wire).
func LessGoTLSDataEventByPerfOrder(a, b *GoTLSDataEvent) bool {
	return a.BpfMonoNs < b.BpfMonoNs
}

// PerfMonoNs implements domain.MonoNsEvent (bpf monotonic time on the wire).
func (e *GoTLSDataEvent) PerfMonoNs() uint64 {
	return e.BpfMonoNs
}

// GetTimestamp returns the event timestamp in nanoseconds.
func (e *GoTLSDataEvent) GetTimestamp() uint64 {
	return e.Timestamp
}

// GetTimestampTime returns the event timestamp as time.Time.
func (e *GoTLSDataEvent) GetTimestampTime() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

// GetPid returns the process ID.
func (e *GoTLSDataEvent) GetPid() uint32 {
	return e.Pid
}

// GetComm returns the process name as a string.
func (e *GoTLSDataEvent) GetComm() string {
	return commToString(e.Comm[:])
}

// GetData returns the TLS data payload.
func (e *GoTLSDataEvent) GetData() []byte {
	dataLen := e.DataLen
	if dataLen < 0 {
		dataLen = 0
	}
	if int(dataLen) > len(e.Data) {
		dataLen = int32(len(e.Data))
	}
	return e.Data[:dataLen]
}

// GetDataLen returns the length of the TLS data.
func (e *GoTLSDataEvent) GetDataLen() uint32 {
	if e.DataLen < 0 {
		return 0
	}
	return uint32(e.DataLen)
}

// GetFd returns the file descriptor.
func (e *GoTLSDataEvent) GetFd() uint32 {
	return e.Fd
}

// GetSrcIP returns the source IP address as string.
func (e *GoTLSDataEvent) GetSrcIP() string {
	return ipToString(e.SrcIP[:], e.IPVersion)
}

// GetDstIP returns the destination IP address as string.
func (e *GoTLSDataEvent) GetDstIP() string {
	return ipToString(e.DstIP[:], e.IPVersion)
}

// GetSrcPort returns the source port.
func (e *GoTLSDataEvent) GetSrcPort() uint16 {
	return e.SrcPort
}

// GetDstPort returns the destination port.
func (e *GoTLSDataEvent) GetDstPort() uint16 {
	return e.DstPort
}

// IsRead returns true if this is a read event.
func (e *GoTLSDataEvent) IsRead() bool {
	return e.EventType == 1 // GOTLS_EVENT_TYPE_READ
}

// IsWrite returns true if this is a write event.
func (e *GoTLSDataEvent) IsWrite() bool {
	return e.EventType == 0 // GOTLS_EVENT_TYPE_WRITE
}

// GetTuple returns the connection tuple string in the canonical [ip]:port->[ip]:port format.
// Result is cached in e.Tuple after the first call (assumes fields are set once via DecodeFromBytes).
func (e *GoTLSDataEvent) GetTuple() string {
	if e.Tuple != "" {
		return e.Tuple
	}
	var localIP, remoteIP string
	var localPort, remotePort uint16
	switch e.IPVersion {
	case 4:
		localIP = ipToString(e.SrcIP[:4], 4)
		remoteIP = ipToString(e.DstIP[:4], 4)
	case 6:
		localIP = ipToString(e.SrcIP[:16], 6)
		remoteIP = ipToString(e.DstIP[:16], 6)
	default:
		e.Tuple = DefaultTuple
		return e.Tuple
	}
	localPort = e.SrcPort
	remotePort = e.DstPort

	var srcIP, dstIP string
	var srcPort, dstPort uint16
	if e.EventType == 0 { // WRITE: local → remote
		srcIP, srcPort = localIP, localPort
		dstIP, dstPort = remoteIP, remotePort
	} else { // READ: remote → local
		srcIP, srcPort = remoteIP, remotePort
		dstIP, dstPort = localIP, localPort
	}

	e.Tuple = fmt.Sprintf("[%s]:%d->[%s]:%d", srcIP, srcPort, dstIP, dstPort)
	return e.Tuple
}

// commToString converts a null-terminated byte array to string.
func commToString(comm []byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}

// ipToString converts a 4-byte or 16-byte IP address to string based on version.
func ipToString(ip []byte, version uint8) string {
	switch version {
	case 4:
		if len(ip) < 4 {
			return ""
		}
		return net.IP(ip[:4]).String()
	case 6:
		if len(ip) < 16 {
			return ""
		}
		return net.IP(ip[:16]).String()
	default:
		return ""
	}
}

// String returns a human-readable representation of the event.
func (e *GoTLSDataEvent) String() string {
	direction := "WRITE"
	if e.IsRead() {
		direction = "READ"
	}
	tuple := e.GetTuple()
	if tuple == "" {
		return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, FD:%d, Type:%s, Len:%d\nData:\n%s",
			e.Pid, e.Tid, commToString(e.Comm[:]), e.Fd, direction, e.DataLen, string(e.GetData()))
	}
	return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, FD:%d, Tuple:%s, Type:%s, Len:%d\nData:\n%s",
		e.Pid, e.Tid, commToString(e.Comm[:]), e.Fd, tuple, direction, e.DataLen, string(e.GetData()))
}

// StringHex returns a hexadecimal representation of the event.
func (e *GoTLSDataEvent) StringHex() string {
	direction := "WRITE"
	if e.IsRead() {
		direction = "READ"
	}
	tuple := e.GetTuple()
	if tuple == "" {
		return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, FD:%d, Type:%s, Len:%d\nData(hex):\n%x",
			e.Pid, e.Tid, commToString(e.Comm[:]), e.Fd, direction, e.DataLen, e.GetData())
	}
	return fmt.Sprintf("PID:%d, TID:%d, Comm:%s, FD:%d, Tuple:%s, Type:%s, Len:%d\nData(hex):\n%x",
		e.Pid, e.Tid, commToString(e.Comm[:]), e.Fd, tuple, direction, e.DataLen, e.GetData())
}

// Clone creates a new empty instance of the event.
func (e *GoTLSDataEvent) Clone() domain.Event {
	return &GoTLSDataEvent{}
}

// Type returns the event type.
func (e *GoTLSDataEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event.
// Due to HTTP2 multiplexing, tid cannot be used as a UUID.
func (e *GoTLSDataEvent) UUID() string {
	return fmt.Sprintf("gotls:%d_%s_%d_%s", e.Pid, commToString(e.Comm[:]), e.Fd, e.GetTuple())
}

// Validate checks if the event data is valid.
func (e *GoTLSDataEvent) Validate() error {
	if e.DataLen > maxGoTLSPayload {
		return fmt.Errorf("data length %d exceeds maximum %d", e.DataLen, maxGoTLSPayload)
	}
	if e.DataLen < 0 {
		return fmt.Errorf("data length %d is negative", e.DataLen)
	}
	return nil
}
