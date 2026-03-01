package openssl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/internal/errors"

	"github.com/gojue/ecapture/internal/domain"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

type connDataEvent struct {
	Saddr       [32]byte `json:"saddr"`
	Daddr       [32]byte `json:"daddr"`
	Comm        [16]byte `json:"Comm"`
	TimestampNs uint64   `json:"timestampNs"`
	Sock        uint64   `json:"sock"`
	Pid         uint32   `json:"pid"`
	Tid         uint32   `json:"tid"`
	Fd          uint32   `json:"fd"`
	Family      uint16   `json:"family"`
	Sport       uint16   `json:"sport"`
	Dport       uint16   `json:"dport"`
	IsDestroy   uint8    `json:"isDestroy"`
	Pad         [7]byte  `json:"-"`

	// NOTE: do not leave padding hole in this struct.
}
type Type uint8
type ConnDataEvent struct {
	connDataEvent
	eventType Type
	Tuple     string `json:"tuple"`
}

func (ce *ConnDataEvent) Type() domain.EventType {
	return domain.EventTypeModuleData
}

func (e *ConnDataEvent) DecodeFromBytes(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err := binary.Read(buf, binary.LittleEndian, &e.Saddr); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Saddr", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Daddr); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Daddr", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Comm", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.TimestampNs); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.TimestampNs", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Sock); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Sock", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Pid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Tid", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Fd); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Fd", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Family); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Family", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Sport); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Sport", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Dport); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.Dport", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.IsDestroy); err != nil {
		return errors.NewEventDecodeError("openssl.ConnDataEvent.IsDestroy", err)
	}

	if e.Family == unix.AF_INET {
		saddr, daddr := netip.AddrFrom4([4]byte(e.Saddr[:4])), netip.AddrFrom4([4]byte(e.Daddr[:4]))
		e.Tuple = fmt.Sprintf("[%s]:%d->[%s]:%d", saddr, e.Sport, daddr, e.Dport)
	} else {
		saddr, daddr := netip.AddrFrom16([16]byte(e.Saddr[16:32])), netip.AddrFrom16([16]byte(e.Daddr[16:32]))
		e.Tuple = fmt.Sprintf("[%s]:%d->[%s]:%d", saddr, e.Sport, daddr, e.Dport)
	}

	return nil
}

func (ce *ConnDataEvent) Validate() error {
	//if ce.Family != unix.AF_INET && ce.Family != unix.AF_INET6 {
	//	return fmt.Errorf("invalid address family: %d", ce.Family)
	//}
	//if ce.Sport == 0 || ce.Dport == 0 {
	//	return fmt.Errorf("invalid port numbers: sport=%d, dport=%d", ce.Sport, ce.Dport)
	//}
	return nil
}

func (ce *ConnDataEvent) Clone() domain.Event {
	clone := *ce
	return &clone
}

func (ce *ConnDataEvent) UUID() string {
	// 临时沿用旧版 UUID 逻辑，新特性尚在开发中。
	return fmt.Sprintf("%d_%d_%s_%d", ce.Pid, ce.Tid, commStr(ce.Comm[:]), ce.Fd)

	// TODO: 新版 UUID 逻辑待启用。新格式增加了 socket 前缀，用于标识与套接字的绑定。
	// return fmt.Sprintf("%s:%d_%d_%s_%d", SocketLifecycleUUIDPrefix, ce.Pid, ce.Tid, commStr(ce.Comm[:]), ce.Fd)
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

func commStr(comm []byte) string {
	return strings.TrimSpace(CToGoString(comm))
}

func (ce *ConnDataEvent) StringHex() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Tuple: %s", ce.Pid, commStr(ce.Comm[:]), ce.Tid, ce.Fd, ce.Tuple)
	return s
}

func (ce *ConnDataEvent) String() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Tuple: %s", ce.Pid, commStr(ce.Comm[:]), ce.Tid, ce.Fd, ce.Tuple)
	return s
}

func (ce *ConnDataEvent) EventType() Type {
	return ce.eventType
}

func (ce *ConnDataEvent) GetUUID() string {
	// 临时沿用旧版 UUID 逻辑，新特性尚在开发中。
	return fmt.Sprintf("%d_%d_%s_%d", ce.Pid, ce.Tid, commStr(ce.Comm[:]), ce.Fd)

	// TODO: 新版 UUID 逻辑待启用。新格式增加了 socket 前缀，用于标识与套接字的绑定。
	// return fmt.Sprintf("%s:%d_%d_%s_%d", SocketLifecycleUUIDPrefix, ce.Pid, ce.Tid, commStr(ce.Comm[:]), ce.Fd)
}

func (ce *ConnDataEvent) ToProtobufEvent() *pb.Event {
	event := &pb.Event{
		Timestamp: int64(ce.TimestampNs),
		Uuid:      ce.GetUUID(),
		Pid:       int64(ce.Pid),
		Pname:     commStr(ce.Comm[:]),
		Type:      0,
		Length:    uint32(len(ce.Tuple)),
		Payload:   []byte(ce.Tuple),
	}

	// Parse tuple for IP addresses and ports
	ips := strings.Split(ce.Tuple, "-")
	if len(ips) == 2 {
		srcParts := strings.Split(ips[0], ":")
		destParts := strings.Split(ips[1], ":")

		if len(srcParts) == 2 && len(destParts) == 2 {
			event.SrcIp = srcParts[0]
			event.DstIp = destParts[0]

			if srcPort, err := strconv.ParseUint(srcParts[1], 10, 32); err == nil {
				event.SrcPort = uint32(srcPort)
			}

			if dstPort, err := strconv.ParseUint(destParts[1], 10, 32); err == nil {
				event.DstPort = uint32(dstPort)
			}
		}
	}

	return event
}

func (ce *ConnDataEvent) Payload() []byte {
	return []byte(ce.Tuple)
}

func (ce *ConnDataEvent) PayloadLen() int {
	return len(ce.Tuple)
}
