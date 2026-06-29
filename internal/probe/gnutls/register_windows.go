//go:build windows
// +build windows

package gnutls

import (
	"context"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/factory"
)

func init() {
	_ = factory.RegisterProbe(factory.ProbeTypeGnuTLS, func() (domain.Probe, error) {
		return &stubProbe{name: string(factory.ProbeTypeGnuTLS)}, nil
	})
}

type stubProbe struct{ name string }

func (p *stubProbe) Initialize(_ context.Context, _ domain.Configuration) error {
	return errors.NewProbeStartError(p.name, errors.New(errors.ErrCodeConfiguration, "GnuTLS probe is not supported on Windows"))
}
func (p *stubProbe) Start(_ context.Context) error                     { return nil }
func (p *stubProbe) Stop(_ context.Context) error                      { return nil }
func (p *stubProbe) Close() error                                      { return nil }
func (p *stubProbe) Name() string                                      { return p.name }
func (p *stubProbe) IsRunning() bool                                   { return false }
func (p *stubProbe) Events() []*ebpf.Map                               { return nil }
func (p *stubProbe) DecodeFun(_ *ebpf.Map) (domain.EventDecoder, bool) { return nil, false }
