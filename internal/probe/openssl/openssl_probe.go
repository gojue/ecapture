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
	"context"
	"fmt"
	"io"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Probe implements the OpenSSL TLS tracing probe (simplified Text mode implementation).
// TODO: This is a Phase 4 Plan B simplified implementation.
// Full implementation with network tracking, Keylog, and Pcap modes will be added in future PRs.
type Probe struct {
	*base.BaseProbe
	config      *Config
	textHandler *handlers.TextHandler
	output      io.Writer
	// TODO: Add in future PRs:
	// bpfManager *manager.Manager
	// eventMaps  []*ebpf.Map
	// connTracker *ConnectionTracker
	// keylogHandler *handlers.KeylogHandler
	// pcapHandler   *handlers.PcapHandler
}

// NewProbe creates a new OpenSSL probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe: base.NewBaseProbe("openssl"),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	// Type assert to OpenSSL-specific config
	opensslConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for openssl probe", nil)
	}
	p.config = opensslConfig

	// Validate that the detected version is supported
	if !p.config.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported OpenSSL version: %s", p.config.SslVersion))
	}

	// Initialize text handler
	if p.output == nil {
		p.output = io.Discard
	}
	p.textHandler = handlers.NewTextHandler(p.output)

	p.Logger().Info().
		Str("openssl_path", opensslConfig.OpensslPath).
		Str("ssl_version", opensslConfig.SslVersion).
		Bool("is_boringssl", opensslConfig.IsBoringSSL).
		Msg("OpenSSL probe initialized")

	return nil
}

// Start begins the OpenSSL probe operation.
// TODO: Phase 4 Plan B - This is a simplified stub implementation.
// Full eBPF implementation will be added in future PRs.
func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	// TODO: Implement eBPF loading and attachment in future PRs
	// Steps to be added:
	// 1. Load eBPF bytecode for the detected OpenSSL version
	// 2. Setup eBPF manager with SSL_read/SSL_write hooks
	// 3. Setup network connection tracking (kprobes for connect/accept)
	// 4. Initialize event maps
	// 5. Start event reader loops

	p.Logger().Info().Msg("OpenSSL probe started (stub implementation - eBPF hooks not yet implemented)")
	p.Logger().Warn().Msg("TODO: Full eBPF implementation pending. This is Phase 4 Plan B placeholder.")

	return nil
}

// Stop gracefully stops the probe.
func (p *Probe) Stop(ctx context.Context) error {
	// TODO: Stop eBPF manager and event readers
	return p.BaseProbe.Stop(ctx)
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	// TODO: Return actual event maps once eBPF is implemented
	return []*ebpf.Map{}
}

// Close releases all probe resources.
func (p *Probe) Close() error {
	// Close text handler
	if p.textHandler != nil {
		if err := p.textHandler.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close text handler")
		}
	}

	// TODO: Close eBPF manager and other resources in future PRs

	return p.BaseProbe.Close()
}

// Decode implements EventDecoder interface.
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}

	// Validate the event
	if err := event.Validate(); err != nil {
		return nil, err
	}

	return event, nil
}

// GetDecoder returns the event decoder for a specific eBPF map.
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	// For OpenSSL, we use the same Event type for all maps
	return &Event{}, true
}

// SetOutput sets the output writer for the probe.
func (p *Probe) SetOutput(w io.Writer) {
	p.output = w
	if p.textHandler != nil {
		p.textHandler = handlers.NewTextHandler(w)
	}
}
