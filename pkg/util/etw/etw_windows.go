//go:build windows
// +build windows

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

package etw

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/gojue/ecapture/internal/errors"
)

var advapi32 = windows.NewLazyDLL("advapi32.dll")

// ETW constants.
const (
	eventTraceRealTimeMode         = 0x00000100
	eventTraceEventRecord          = 0x10000000
	wnodeFlagTracedGUID            = 0x00020000
	eventTraceControlStop          = 1
	eventControlCodeEnableProvider = 1
	traceLevelInformation          = 4
	propsHeaderSize                = 84
)

// Well-known ETW Provider GUIDs.
var (
	SchannelProvider                 = GUID{0x1F678132, 0x61B8, 0x4CF3, [8]byte{0xB5, 0x92, 0x70, 0xB3, 0x01, 0x53, 0x18, 0xC0}}
	MicrosoftWindowsWinINet          = GUID{0xA85CB4B5, 0x3943, 0x4F06, [8]byte{0xB5, 0x71, 0xB3, 0x55, 0x20, 0x57, 0x13, 0xE2}}
	MicrosoftWindowsTCPIP            = GUID{0xEB9C4F35, 0x5B65, 0x4B3E, [8]byte{0x86, 0xD0, 0x35, 0x31, 0x60, 0x19, 0x7F, 0xE2}}
	MicrosoftWindowsPowerShell       = GUID{0xA0C1853B, 0x5C40, 0x4B15, [8]byte{0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x62, 0x6E, 0xE0}}
	MicrosoftWindowsDotNETRuntime    = GUID{0xE13C0D23, 0xCCBC, 0x4E12, [8]byte{0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4}}
	MicrosoftWindowsSecurityAuditing = GUID{0x54849625, 0x5478, 0x4994, [8]byte{0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D}}
)

// GUID represents a Windows GUID.
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

// TraceHandle identifies an ETW session or trace consumer.
type TraceHandle uint64

// InvalidTraceHandle represents an uninitialized trace handle.
const InvalidTraceHandle TraceHandle = 0xFFFFFFFFFFFFFFFF

// EventCallback is invoked for each decoded ETW event.
type EventCallback func(event *EventRecord)

// EventRecord represents a decoded ETW event.
type EventRecord struct {
	ProviderId GUID
	EventId    uint16
	Version    uint8
	ProcessId  uint32
	ThreadId   uint32
	Timestamp  int64 // 100-nanosecond intervals since Jan 1, 1601
	UserData   []byte
	Properties map[string]any
}

// SessionConfig holds configuration for an ETW tracing session.
type SessionConfig struct {
	SessionName string
	Providers   []GUID
	BufferSize  uint32 // KB, default 64
	MinBuffers  uint32 // default 4
	MaxBuffers  uint32 // default 16
	FlushTimer  uint32 // seconds, default 1
	Callback    EventCallback
}

// Session represents an ETW tracing session.
type Session struct {
	mu          sync.Mutex
	handle      TraceHandle
	traceHandle TraceHandle
	sessionName string
	providers   []GUID
	callback    EventCallback
	bufferSize  uint32
	minBuffers  uint32
	maxBuffers  uint32
	flushTimer  uint32
	running     atomic.Bool
	stopCh      chan struct{}
	processWg   sync.WaitGroup
}

// NewSession creates a new ETW session with the provided configuration.
func NewSession(config SessionConfig) (*Session, error) {
	if config.SessionName == "" {
		return nil, errors.New(errors.ErrCodeConfiguration, "session name is required")
	}
	if config.Callback == nil {
		return nil, errors.New(errors.ErrCodeConfiguration, "event callback is required")
	}
	if config.BufferSize == 0 {
		config.BufferSize = 64
	}
	if config.MinBuffers == 0 {
		config.MinBuffers = 4
	}
	if config.MaxBuffers == 0 {
		config.MaxBuffers = 16
	}
	if config.FlushTimer == 0 {
		config.FlushTimer = 1
	}
	return &Session{
		handle:      InvalidTraceHandle,
		traceHandle: InvalidTraceHandle,
		sessionName: config.SessionName,
		providers:   config.Providers,
		callback:    config.Callback,
		bufferSize:  config.BufferSize,
		minBuffers:  config.MinBuffers,
		maxBuffers:  config.MaxBuffers,
		flushTimer:  config.FlushTimer,
	}, nil
}

// Start begins the ETW session and starts processing events.
func (s *Session) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running.Load() {
		return errors.New(errors.ErrCodeProbeStart, "session already running")
	}
	if !IsAdmin() {
		return errors.New(errors.ErrCodeProbeStart, "ETW sessions require administrator privileges")
	}

	if err := s.startTrace(); err != nil {
		return err
	}

	s.stopCh = make(chan struct{})
	s.running.Store(true)
	s.processWg.Add(1)
	go s.processEvents()
	return nil
}

// Stop gracefully stops the ETW session.
func (s *Session) Stop() error {
	s.mu.Lock()
	if !s.running.Load() {
		s.mu.Unlock()
		return nil
	}
	s.running.Store(false)
	close(s.stopCh)
	s.mu.Unlock()

	// Wait for the consumer loop to finish before closing the session handle.
	s.processWg.Wait()

	return s.stopTrace()
}

// IsRunning returns whether the session is currently active.
func (s *Session) IsRunning() bool {
	return s.running.Load()
}

// startTrace calls StartTraceW with a properly laid-out EVENT_TRACE_PROPERTIES buffer.
func (s *Session) startTrace() error {
	startTraceProc := advapi32.NewProc("StartTraceW")

	sessionNameUTF16, err := windows.UTF16FromString(s.sessionName)
	if err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "convert session name", err)
	}
	sessionNameBytes := len(sessionNameUTF16) * 2

	// EVENT_TRACE_PROPERTIES layout (64-bit):
	//   [0..47]   WNODE_HEADER (48 bytes)
	//   [48..51]  BufferSize
	//   [52..55]  MinimumBuffers
	//   [56..59]  MaximumBuffers
	//   [60..63]  MaximumFileSize
	//   [64..67]  LogFileMode
	//   [68..71]  FlushTimer
	//   [72..75]  AgeLimit
	//   [76..79]  LoggerNameOffset
	//   [80..83]  LogFileNameOffset
	loggerNameOffset := propsHeaderSize
	totalSize := propsHeaderSize + sessionNameBytes + 2 // +2 for null terminator

	props := make([]byte, totalSize)

	// Wnode.BufferSize (offset 0)
	*(*uint32)(unsafe.Pointer(&props[0])) = uint32(totalSize)
	// Wnode.Flags = WNODE_FLAG_TRACED_GUID (offset 8)
	*(*uint32)(unsafe.Pointer(&props[8])) = wnodeFlagTracedGUID

	// BufferSize (offset 48)
	*(*uint32)(unsafe.Pointer(&props[48])) = s.bufferSize
	// MinimumBuffers (offset 52)
	*(*uint32)(unsafe.Pointer(&props[52])) = s.minBuffers
	// MaximumBuffers (offset 56)
	*(*uint32)(unsafe.Pointer(&props[56])) = s.maxBuffers
	// LogFileMode (offset 64) = EVENT_TRACE_REAL_TIME_MODE
	*(*uint32)(unsafe.Pointer(&props[64])) = eventTraceRealTimeMode
	// FlushTimer (offset 68)
	*(*uint32)(unsafe.Pointer(&props[68])) = s.flushTimer
	// LoggerNameOffset (offset 76)
	*(*uint32)(unsafe.Pointer(&props[76])) = uint32(loggerNameOffset)

	// Copy session name into buffer at LoggerNameOffset
	for i, ch := range sessionNameUTF16 {
		*(*uint16)(unsafe.Pointer(&props[loggerNameOffset+i*2])) = ch
	}

	var traceHandle TraceHandle
	ret, _, _ := startTraceProc.Call(
		uintptr(unsafe.Pointer(&traceHandle)),
		uintptr(unsafe.Pointer(&sessionNameUTF16[0])),
		uintptr(unsafe.Pointer(&props[0])),
	)

	if ret != 0 {
		return errors.New(errors.ErrCodeProbeStart, fmt.Sprintf("StartTraceW failed: error code %d", ret))
	}

	s.handle = traceHandle

	for _, provider := range s.providers {
		if err := s.enableProvider(provider); err != nil {
			_ = s.stopTrace()
			return errors.Wrap(errors.ErrCodeProbeStart, "enable provider", err).WithContext("provider", provider.String())
		}
	}
	return nil
}

func (s *Session) enableProvider(provider GUID) error {
	enableTraceEx2 := advapi32.NewProc("EnableTraceEx2")

	ret, _, _ := enableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&provider)),
		eventControlCodeEnableProvider,
		traceLevelInformation,
		0, 0, 0, 0,
	)

	if ret != 0 {
		return errors.New(errors.ErrCodeProbeStart, fmt.Sprintf("EnableTraceEx2 failed: error code %d", ret))
	}
	return nil
}

func (s *Session) processEvents() {
	defer s.processWg.Done()

	logfile := newEventTraceLogfile(s.sessionName)
	logfile.Context = uintptr(unsafe.Pointer(s))
	logfile.ProcessTraceMode = eventTraceRealTimeMode | eventTraceEventRecord
	logfile.EventRecordCallback = syscall.NewCallback(processEventCallback)

	openTraceProc := advapi32.NewProc("OpenTraceW")
	traceHandle, _, _ := openTraceProc.Call(uintptr(unsafe.Pointer(logfile)))
	if traceHandle == uintptr(InvalidTraceHandle) {
		return
	}

	s.mu.Lock()
	s.traceHandle = TraceHandle(traceHandle)
	s.mu.Unlock()

	processTraceProc := advapi32.NewProc("ProcessTrace")
	ret, _, _ := processTraceProc.Call(
		uintptr(unsafe.Pointer(&s.traceHandle)),
		1,
		0,
		0,
	)
	_ = ret

	// Keep the callback and logfile descriptor alive until ProcessTrace returns.
	runtime.KeepAlive(logfile)
	runtime.KeepAlive(processEventCallback)

	closeTraceProc := advapi32.NewProc("CloseTrace")
	_, _, _ = closeTraceProc.Call(traceHandle)

	s.mu.Lock()
	s.traceHandle = InvalidTraceHandle
	s.mu.Unlock()
}

// stopTrace stops the ETW session.
func (s *Session) stopTrace() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handle == InvalidTraceHandle {
		return nil
	}

	// ControlTraceW requires a valid EVENT_TRACE_PROPERTIES buffer even when
	// stopping via handle. Allocate one large enough for the session name.
	sessionNameUTF16, err := windows.UTF16FromString(s.sessionName)
	if err != nil {
		s.handle = InvalidTraceHandle
		return errors.Wrap(errors.ErrCodeProbeStop, "convert session name", err)
	}
	sessionNameBytes := len(sessionNameUTF16) * 2
	loggerNameOffset := propsHeaderSize
	totalSize := propsHeaderSize + sessionNameBytes + 2

	props := make([]byte, totalSize)
	*(*uint32)(unsafe.Pointer(&props[0])) = uint32(totalSize)
	*(*uint32)(unsafe.Pointer(&props[8])) = wnodeFlagTracedGUID
	*(*uint32)(unsafe.Pointer(&props[76])) = uint32(loggerNameOffset)
	for i, ch := range sessionNameUTF16 {
		*(*uint16)(unsafe.Pointer(&props[loggerNameOffset+i*2])) = ch
	}

	controlTrace := advapi32.NewProc("ControlTraceW")
	ret, _, _ := controlTrace.Call(
		uintptr(s.handle),
		0,
		uintptr(unsafe.Pointer(&props[0])),
		eventTraceControlStop,
	)

	s.handle = InvalidTraceHandle
	if ret != 0 {
		return errors.New(errors.ErrCodeProbeStop, fmt.Sprintf("ControlTrace STOP failed: error code %d", ret))
	}
	return nil
}

// processEventCallback is the C-callable callback for ETW events.
func processEventCallback(pEventRecord unsafe.Pointer) {
	if pEventRecord == nil {
		return
	}
	raw := (*eventRecord)(pEventRecord)

	session := (*Session)(unsafe.Pointer(raw.UserContext))
	if session == nil || session.callback == nil {
		return
	}

	userData := make([]byte, raw.UserDataLength)
	if raw.UserDataLength > 0 && raw.UserData != nil {
		copy(userData, (*[1 << 30]byte)(raw.UserData)[:raw.UserDataLength:raw.UserDataLength])
	}

	event := &EventRecord{
		ProviderId: guidFromNative(&raw.EventHeader.ProviderId),
		EventId:    raw.EventHeader.EventDescriptor.Id,
		Version:    raw.EventHeader.EventDescriptor.Version,
		ProcessId:  raw.EventHeader.ProcessId,
		ThreadId:   raw.EventHeader.ThreadId,
		Timestamp:  raw.EventHeader.TimeStamp,
		UserData:   userData,
		Properties: make(map[string]any),
	}

	// Parse Schannel-specific properties when applicable.
	if event.ProviderId == SchannelProvider {
		ParseSchannelEvent(event)
	}

	session.callback(event)
}

// IsAdmin checks if the current process has administrator privileges.
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	var token windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// eventRecord mirrors the native EVENT_RECORD structure.
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      unsafe.Pointer
	UserData          unsafe.Pointer
	UserContext       uintptr
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      guidNative
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityId      guidNative
}

type eventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type etwBufferContext struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerId        uint16
}

type guidNative struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func guidFromNative(g *guidNative) GUID {
	return GUID{g.Data1, g.Data2, g.Data3, g.Data4}
}

// eventTraceLogfile mirrors EVENT_TRACE_LOGFILEW for OpenTraceW.
type eventTraceLogfile struct {
	StartTime           int64
	EndTime             int64
	TimerResolution     uint32
	Reserved            uint32
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventRecord
	LogfileHeader       [1112]byte // TRACE_LOGFILE_HEADER opaque placeholder
	LoggerName          *uint16
	LogfileName         *uint16
	Context             uintptr
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Reserved2           uint32
}

func newEventTraceLogfile(sessionName string) *eventTraceLogfile {
	nameUTF16, _ := windows.UTF16PtrFromString(sessionName)
	return &eventTraceLogfile{
		LoggerName:       nameUTF16,
		ProcessTraceMode: eventTraceRealTimeMode | eventTraceEventRecord,
	}
}
