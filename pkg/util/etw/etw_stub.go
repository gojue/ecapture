//go:build !windows
// +build !windows

package etw

import (
	"fmt"

	"github.com/gojue/ecapture/internal/errors"
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g GUID) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

type TraceHandle uint64

const InvalidTraceHandle TraceHandle = 0xFFFFFFFFFFFFFFFF

type EventCallback func(event *EventRecord)

type EventRecord struct {
	ProviderId GUID
	EventId    uint16
	Version    uint8
	ProcessId  uint32
	ThreadId   uint32
	Timestamp  int64
	UserData   []byte
	Properties map[string]any
}

type Session struct{}

type SessionConfig struct {
	SessionName string
	Providers   []GUID
	BufferSize  uint32
	MinBuffers  uint32
	MaxBuffers  uint32
	FlushTimer  uint32
	Callback    EventCallback
}

func NewSession(_ SessionConfig) (*Session, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "ETW is only supported on Windows")
}
func (s *Session) Start() error {
	return errors.New(errors.ErrCodeConfiguration, "ETW is only supported on Windows")
}
func (s *Session) Stop() error     { return nil }
func (s *Session) IsRunning() bool { return false }
func IsAdmin() bool                { return false }
