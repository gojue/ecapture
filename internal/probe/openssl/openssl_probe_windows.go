//go:build windows
// +build windows

package openssl

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/factory"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/output/writers"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
	"github.com/gojue/ecapture/pkg/util/etw"
	"github.com/gojue/ecapture/pkg/util/hook"
	winpcap "github.com/gojue/ecapture/pkg/util/pcap"
)

// Probe implements TLS tracing for Windows using ETW Schannel and/or OpenSSL hooking.
type Probe struct {
	name      string
	logger    *logger.Logger
	config    *Config
	isRunning atomic.Bool

	etwSession  *etw.Session
	hookManager *hook.HookManager
	pcapCapture *winpcap.Capture
	dispatcher  domain.EventDispatcher
}

func NewProbe() (*Probe, error) {
	return &Probe{name: string(factory.ProbeTypeOpenSSL)}, nil
}

func (p *Probe) Initialize(_ context.Context, cfg domain.Configuration) error {
	if cfg == nil {
		return errors.NewConfigurationError("configuration cannot be nil", nil)
	}
	if err := cfg.Validate(); err != nil {
		return errors.NewConfigurationError("invalid configuration", err)
	}

	opensslConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for openssl probe", nil)
	}
	p.config = opensslConfig
	p.logger = base.NewLogger(p.name, p.config.GetDebug())

	p.logger.Info().
		Uint64("pid", p.config.GetPid()).
		Bool("use_schannel", p.config.UseSchannel).
		Bool("hook_openssl", p.config.HookOpenSSL).
		Msg("Probe initialized")

	dispatcher, err := base.InitDispatcher(p.name, cfg)
	if err != nil {
		return err
	}
	p.dispatcher = dispatcher

	// Setup keylog handler if needed
	if p.config.CaptureMode == handlers.ModeKeylog || p.config.CaptureMode == handlers.ModeKey {
		if keylogFile := p.config.GetKeylogFile(); keylogFile != "" {
			fw, err := writers.NewFileWriter(writers.FileWriterConfig{Path: keylogFile, Truncate: true})
			if err != nil {
				p.logger.Warn().Err(err).Msg("Failed to create keylog writer")
			} else {
				klWriter := writers.NewKeylogWriter(fw)
				if err := dispatcher.Register(handlers.NewKeylogHandler(klWriter)); err != nil {
					_ = klWriter.Close()
					return errors.Wrap(errors.ErrCodeEventDispatch, "register keylog handler", err)
				}
				p.logger.Info().Str("keylog_file", keylogFile).Msg("Keylog handler registered")
			}
		}
	}

	// Setup pcap handler if needed
	if p.config.CaptureMode == handlers.ModePcap || p.config.CaptureMode == handlers.ModePcapng {
		if pcapFile := p.config.PcapFile; pcapFile != "" {
			fw, err := writers.NewFileWriter(writers.FileWriterConfig{Path: pcapFile, Truncate: true})
			if err != nil {
				p.logger.Warn().Err(err).Msg("Failed to create pcap file writer")
			} else {
				pcapHandler, err := handlers.NewPcapHandler(fw, p.config.Ifname, p.config.PcapFilter, p.logger)
				if err != nil {
					_ = fw.Close()
					return errors.Wrap(errors.ErrCodeEventDispatch, "create pcap handler", err)
				}
				if err := dispatcher.Register(pcapHandler); err != nil {
					_ = pcapHandler.Close()
					return errors.Wrap(errors.ErrCodeEventDispatch, "register pcap handler", err)
				}
				p.logger.Info().Str("pcap_file", pcapFile).Str("interface", p.config.Ifname).Msg("Pcap handler registered")
			}
		}
	}

	return nil
}

func (p *Probe) Start(_ context.Context) error {
	if p.isRunning.Load() {
		return errors.NewProbeStartError(p.name, errors.New(errors.ErrCodeProbeStart, "probe already running"))
	}
	p.isRunning.Store(true)

	if p.config.UseSchannel {
		if err := p.startETWSession(); err != nil {
			p.isRunning.Store(false)
			return err
		}
	}

	if p.config.HookOpenSSL {
		p.hookManager = hook.NewHookManager()
		if err := p.installOpenSSLHooks(); err != nil {
			p.isRunning.Store(false)
			return errors.NewProbeStartError(p.name, err)
		}
	}

	if p.config.CaptureMode == handlers.ModePcap || p.config.CaptureMode == handlers.ModePcapng {
		pcapCapture, err := winpcap.NewCapture(winpcap.Config{
			IfName:     p.config.Ifname,
			Filter:     p.config.PcapFilter,
			Snaplen:    65535,
			Dispatcher: p.dispatcher,
			Logger:     p.logger,
		})
		if err != nil {
			p.isRunning.Store(false)
			return errors.NewProbeStartError(p.name, err)
		}
		if err := pcapCapture.Start(); err != nil {
			p.isRunning.Store(false)
			return errors.NewProbeStartError(p.name, err)
		}
		p.pcapCapture = pcapCapture
	}

	p.logger.Info().
		Str("capture_mode", p.config.CaptureMode).
		Bool("schannel", p.config.UseSchannel).
		Bool("openssl_hook", p.config.HookOpenSSL).
		Msg("Windows TLS probe started")
	return nil
}

func (p *Probe) startETWSession() error {
	session, err := etw.NewSession(etw.SessionConfig{
		SessionName: fmt.Sprintf("eCapture-%s-%d", p.name, time.Now().UnixNano()),
		Providers:   []etw.GUID{etw.SchannelProvider},
		Callback:    p.handleETWEvent,
	})
	if err != nil {
		return errors.NewProbeStartError(p.name, err)
	}
	if err := session.Start(); err != nil {
		return errors.NewProbeStartError(p.name, err)
	}
	p.etwSession = session
	p.logger.Info().Str("provider", etw.SchannelProvider.String()).Msg("ETW Schannel session started")
	return nil
}

func (p *Probe) handleETWEvent(event *etw.EventRecord) {
	if p.config.GetPid() != 0 && uint64(event.ProcessId) != p.config.GetPid() {
		return
	}
	domainEvent := &WindowsTLSEvent{
		eventType:  event.EventId,
		processId:  event.ProcessId,
		threadId:   event.ThreadId,
		timestamp:  event.Timestamp,
		properties: event.Properties,
		userData:   event.UserData,
	}
	if err := p.dispatcher.Dispatch(domainEvent); err != nil {
		p.logger.Warn().Err(err).Msg("Failed to dispatch ETW event")
	}
}

func (p *Probe) installOpenSSLHooks() error {
	dllPath := p.config.OpenSSLDll
	if dllPath == "" {
		return errors.New(errors.ErrCodeConfiguration, "OpenSSL DLL path not set")
	}

	for _, fn := range []string{"SSL_read", "SSL_write"} {
		fn := fn // capture loop variable for closure
		if err := p.hookManager.AddHook(fn, hook.HookConfig{
			Module:   dllPath,
			FuncName: fn,
			Callback: func(addr uintptr, pid uint32, args []uintptr) {
				p.logger.Debug().Str("func", fn).Uint32("pid", pid).Msg("OpenSSL function intercepted")
			},
		}); err != nil {
			p.logger.Warn().Err(err).Str("func", fn).Msg("Failed to hook OpenSSL function")
		}
	}
	return nil
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
	if p.hookManager != nil {
		_ = p.hookManager.Close()
		p.hookManager = nil
	}
	if p.pcapCapture != nil {
		_ = p.pcapCapture.Stop()
		p.pcapCapture = nil
	}

	p.logger.Info().Msg("Windows TLS probe stopped")
	return nil
}

func (p *Probe) Close() error {
	_ = p.Stop(context.Background())
	p.isRunning.Store(false)
	base.CloseDispatcher(p.dispatcher, p.logger)
	p.logger.Info().Msg("Windows TLS probe closed")
	return nil
}

func (p *Probe) Name() string        { return p.name }
func (p *Probe) IsRunning() bool     { return p.isRunning.Load() }
func (p *Probe) Events() []*ebpf.Map { return nil }

// WindowsTLSEvent represents a TLS event captured via ETW or hooking.
type WindowsTLSEvent struct {
	eventType  uint16
	processId  uint32
	threadId   uint32
	timestamp  int64
	properties map[string]any
	userData   []byte
}

func (e *WindowsTLSEvent) DecodeFromBytes(data []byte) error { e.userData = data; return nil }
func (e *WindowsTLSEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (e *WindowsTLSEvent) Validate() error                   { return nil }
func (e *WindowsTLSEvent) StringHex() string                 { return fmt.Sprintf("%x", e.userData) }
func (e *WindowsTLSEvent) UUID() string {
	return fmt.Sprintf("win-tls-%d-%d-%d", e.processId, e.threadId, e.timestamp)
}

func (e *WindowsTLSEvent) String() string {
	protocol, cipher, target := "", "", ""
	if v, ok := e.properties[etw.PropProtocol]; ok {
		if proto, ok := v.(uint32); ok {
			protocol = etw.ProtocolName(proto)
		}
	}
	if v, ok := e.properties[etw.PropCipherSuite]; ok {
		cipher = fmt.Sprintf("%v", v)
	}
	if v, ok := e.properties[etw.PropTargetName]; ok {
		target = fmt.Sprintf("%v", v)
	}
	return fmt.Sprintf("PID:%d TID:%d TLS(%d) Proto:%s Cipher:%s Target:%s",
		e.processId, e.threadId, e.eventType, protocol, cipher, target)
}

func (e *WindowsTLSEvent) Clone() domain.Event {
	c := &WindowsTLSEvent{
		eventType: e.eventType, processId: e.processId,
		threadId: e.threadId, timestamp: e.timestamp,
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
