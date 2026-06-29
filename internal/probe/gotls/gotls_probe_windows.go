//go:build windows
// +build windows

package gotls

import (
	"context"
	"sync/atomic"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/factory"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/pkg/util/hook"
)

// Probe implements Go TLS tracing for Windows using function hooking.
type Probe struct {
	name      string
	logger    *logger.Logger
	config    *Config
	isRunning atomic.Bool

	hookManager *hook.HookManager
	dispatcher  domain.EventDispatcher
}

func NewProbe() (*Probe, error) {
	return &Probe{name: string(factory.ProbeTypeGoTLS)}, nil
}

func (p *Probe) Initialize(_ context.Context, cfg domain.Configuration) error {
	if cfg == nil {
		return errors.NewConfigurationError("configuration cannot be nil", nil)
	}
	if err := cfg.Validate(); err != nil {
		return errors.NewConfigurationError("invalid configuration", err)
	}

	gotlsConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for gotls probe", nil)
	}
	p.config = gotlsConfig
	p.logger = base.NewLogger(p.name, p.config.GetDebug())

	p.logger.Info().
		Uint64("pid", p.config.GetPid()).
		Str("binary", p.config.Path).
		Msg("GoTLS probe initialized")

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
	p.hookManager = hook.NewHookManager()

	// TODO: implement Go binary PE symbol parsing to find crypto/tls.(*Conn).Read/Write
	// and install hooks via hookManager.

	p.logger.Info().Str("binary", p.config.Path).Msg("Windows GoTLS probe started")
	return nil
}

func (p *Probe) Stop(_ context.Context) error {
	if !p.isRunning.Load() {
		return nil
	}
	p.isRunning.Store(false)
	if p.hookManager != nil {
		_ = p.hookManager.Close()
		p.hookManager = nil
	}
	p.logger.Info().Msg("Windows GoTLS probe stopped")
	return nil
}

func (p *Probe) Close() error {
	_ = p.Stop(context.Background())
	p.isRunning.Store(false)
	base.CloseDispatcher(p.dispatcher, p.logger)
	p.logger.Info().Msg("Windows GoTLS probe closed")
	return nil
}

func (p *Probe) Name() string        { return p.name }
func (p *Probe) IsRunning() bool     { return p.isRunning.Load() }
func (p *Probe) Events() []*ebpf.Map { return nil }
