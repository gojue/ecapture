//go:build windows
// +build windows

package bash

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/factory"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/pkg/util/etw"
)

// Probe implements shell command tracing for Windows using ETW.
type Probe struct {
	name      string
	logger    *logger.Logger
	config    *Config
	isRunning atomic.Bool

	etwSession *etw.Session
	dispatcher domain.EventDispatcher
}

func NewProbe() (*Probe, error) {
	return &Probe{name: string(factory.ProbeTypeBash)}, nil
}

func (p *Probe) Initialize(_ context.Context, cfg domain.Configuration) error {
	if cfg == nil {
		return errors.NewConfigurationError("configuration cannot be nil", nil)
	}
	if err := cfg.Validate(); err != nil {
		return errors.NewConfigurationError("invalid configuration", err)
	}

	bashConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for bash probe", nil)
	}
	p.config = bashConfig
	p.logger = base.NewLogger(p.name, p.config.GetDebug())

	p.logger.Info().
		Uint64("pid", p.config.GetPid()).
		Str("shell", p.config.Bashpath).
		Str("type", p.config.ShellType).
		Msg("Probe initialized")

	dispatcher, err := base.InitDispatcher(p.name, cfg)
	if err != nil {
		return err
	}
	p.dispatcher = dispatcher
	return nil
}

func (p *Probe) Start(_ context.Context) error {
	if p.isRunning.Load() {
		return errors.NewProbeStartError(p.name, errors.New(errors.ErrCodeProbeStart, "probe already running"))
	}
	p.isRunning.Store(true)

	providers := p.getETWProviders()
	session, err := etw.NewSession(etw.SessionConfig{
		SessionName: fmt.Sprintf("eCapture-bash-%d", p.config.GetPid()),
		Providers:   providers,
		Callback:    p.handleETWEvent,
	})
	if err != nil {
		p.isRunning.Store(false)
		return errors.NewProbeStartError(p.name, err)
	}
	if err := session.Start(); err != nil {
		p.isRunning.Store(false)
		return errors.NewProbeStartError(p.name, err)
	}
	p.etwSession = session

	p.logger.Info().Str("shell_type", p.config.ShellType).Msg("Windows shell probe started")
	return nil
}

func (p *Probe) getETWProviders() []etw.GUID {
	switch p.config.ShellType {
	case "powershell":
		return []etw.GUID{etw.MicrosoftWindowsPowerShell}
	default:
		return []etw.GUID{etw.MicrosoftWindowsSecurityAuditing}
	}
}

func (p *Probe) handleETWEvent(event *etw.EventRecord) {
	if p.config.GetPid() != 0 && uint64(event.ProcessId) != p.config.GetPid() {
		return
	}
	domainEvent := &WindowsShellEvent{
		eventType:  event.EventId,
		processId:  event.ProcessId,
		threadId:   event.ThreadId,
		timestamp:  event.Timestamp,
		properties: event.Properties,
		userData:   event.UserData,
		shellType:  p.config.ShellType,
	}
	if err := p.dispatcher.Dispatch(domainEvent); err != nil {
		p.logger.Warn().Err(err).Msg("Failed to dispatch shell event")
	}
}

func (p *Probe) Stop(_ context.Context) error {
	if !p.isRunning.Load() {
		return nil
	}
	p.isRunning.Store(false)
	if p.etwSession != nil {
		if err := p.etwSession.Stop(); err != nil {
			p.logger.Warn().Err(err).Msg("Failed to stop ETW session")
		}
	}
	p.logger.Info().Msg("Windows shell probe stopped")
	return nil
}

func (p *Probe) Close() error {
	_ = p.Stop(context.Background())
	p.isRunning.Store(false)
	base.CloseDispatcher(p.dispatcher, p.logger)
	p.logger.Info().Msg("Windows shell probe closed")
	return nil
}

func (p *Probe) Name() string        { return p.name }
func (p *Probe) IsRunning() bool     { return p.isRunning.Load() }
func (p *Probe) Events() []*ebpf.Map { return nil }

// WindowsShellEvent represents a shell command event captured on Windows.
type WindowsShellEvent struct {
	eventType  uint16
	processId  uint32
	threadId   uint32
	timestamp  int64
	properties map[string]any
	userData   []byte
	shellType  string
}

func (e *WindowsShellEvent) DecodeFromBytes(data []byte) error { e.userData = data; return nil }
func (e *WindowsShellEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (e *WindowsShellEvent) Validate() error                   { return nil }
func (e *WindowsShellEvent) StringHex() string                 { return fmt.Sprintf("%x", e.userData) }
func (e *WindowsShellEvent) UUID() string {
	return fmt.Sprintf("win-shell-%d-%d-%d", e.processId, e.threadId, e.timestamp)
}

func (e *WindowsShellEvent) String() string {
	command := ""
	if v, ok := e.properties["CommandLine"]; ok {
		command = fmt.Sprintf("%v", v)
	} else if len(e.userData) > 0 {
		command = string(e.userData)
	}
	return fmt.Sprintf("PID:%d [%s] %s", e.processId, e.shellType, command)
}

func (e *WindowsShellEvent) Clone() domain.Event {
	c := &WindowsShellEvent{
		eventType: e.eventType, processId: e.processId,
		threadId: e.threadId, timestamp: e.timestamp, shellType: e.shellType,
	}
	if e.properties != nil {
		c.properties = make(map[string]any, len(e.properties))
		for k, v := range e.properties {
			c.properties[k] = v
		}
	}
	if e.userData != nil {
		c.userData = make([]byte, len(e.userData))
		copy(c.userData, e.userData)
	}
	return c
}
