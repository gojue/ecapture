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

package base

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/logger"
)

// BaseProbe provides common functionality for all probes.
// Concrete probes should embed this struct and implement probe-specific logic.
type BaseProbe struct {
	name       string
	logger     *logger.Logger
	ctx        context.Context
	config     domain.Configuration
	dispatcher domain.EventDispatcher
	isRunning  atomic.Bool
	readers    []closer
}

// closer interface for resources that need to be closed.
type closer interface {
	Close() error
}

// NewBaseProbe creates a new BaseProbe instance.
func NewBaseProbe(name string) *BaseProbe {
	return &BaseProbe{
		name:    name,
		readers: make([]closer, 0),
	}
}

// Initialize sets up the probe with configuration and dependencies.
func (p *BaseProbe) Initialize(ctx context.Context, config domain.Configuration, dispatcher domain.EventDispatcher) error {
	if config == nil {
		return errors.NewConfigurationError("configuration cannot be nil", nil)
	}
	if dispatcher == nil {
		return errors.NewConfigurationError("dispatcher cannot be nil", nil)
	}

	if err := config.Validate(); err != nil {
		return errors.NewConfigurationError("invalid configuration", err)
	}

	p.ctx = ctx
	p.config = config
	p.dispatcher = dispatcher

	// Create a logger with probe name
	p.logger = logger.New(nil, config.GetDebug()).WithProbe(p.name)

	p.logger.Info().
		Uint64("pid", config.GetPid()).
		Uint64("uid", config.GetUid()).
		Msg("Probe initialized")

	return nil
}

// Start begins the probe's operation.
// Concrete probes should override this method to implement probe-specific startup.
func (p *BaseProbe) Start(ctx context.Context) error {
	if p.isRunning.Load() {
		return errors.NewProbeStartError(p.name, fmt.Errorf("probe already running"))
	}

	p.isRunning.Store(true)
	p.logger.Info().Msg("Probe started")
	return nil
}

// Stop gracefully stops the probe.
func (p *BaseProbe) Stop(ctx context.Context) error {
	if !p.isRunning.Load() {
		return nil
	}

	p.isRunning.Store(false)
	p.logger.Info().Msg("Probe stopped")
	return nil
}

// GetBPFName returns the appropriate eBPF bytecode filename.
func (p *BaseProbe) GetBPFName(baseName string) string {
	// Determine if we should use core or non-core bytecode
	useCoreMode := p.config.GetBTF() == 1 // BTFModeCore

	// Replace .o extension
	if useCoreMode {
		return baseName[:len(baseName)-2] + "_core.o"
	}
	return baseName[:len(baseName)-2] + "_noncore.o"
}

// Close releases all resources.
func (p *BaseProbe) Close() error {
	p.isRunning.Store(false)

	// Close all readers in reverse order
	for i := len(p.readers) - 1; i >= 0; i-- {
		if err := p.readers[i].Close(); err != nil {
			p.logger.Warn().
				Err(err).
				Int("reader_index", i).
				Msg("Failed to close reader")
		}
	}

	p.readers = nil
	p.logger.Info().Msg("Probe closed")
	return nil
}

// Name returns the probe's identifier.
func (p *BaseProbe) Name() string {
	return p.name
}

// IsRunning returns whether the probe is currently active.
func (p *BaseProbe) IsRunning() bool {
	return p.isRunning.Load()
}

// Events returns the eBPF maps used for event collection.
// Concrete probes should override this method.
func (p *BaseProbe) Events() []*ebpf.Map {
	return nil
}

// Config returns the probe's configuration.
func (p *BaseProbe) Config() domain.Configuration {
	return p.config
}

// Logger returns the probe's logger.
func (p *BaseProbe) Logger() *logger.Logger {
	return p.logger
}

// Dispatcher returns the event dispatcher.
func (p *BaseProbe) Dispatcher() domain.EventDispatcher {
	return p.dispatcher
}

// Context returns the probe's context.
func (p *BaseProbe) Context() context.Context {
	return p.ctx
}

// StartPerfEventReader starts a perf event reader for the given map.
func (p *BaseProbe) StartPerfEventReader(em *ebpf.Map, decoder domain.EventDecoder) error {
	if em == nil {
		return errors.New(errors.ErrCodeEBPFMapAccess, "eBPF map cannot be nil")
	}
	if decoder == nil {
		return errors.New(errors.ErrCodeConfiguration, "event decoder cannot be nil")
	}

	mapSize := p.config.GetPerCpuMapSize()
	rd, err := perf.NewReader(em, mapSize)
	if err != nil {
		return errors.NewEBPFAttachError(em.String(), err)
	}

	p.readers = append(p.readers, rd)

	p.logger.Info().
		Str("map", em.String()).
		Int("size_mb", mapSize/1024/1024).
		Msg("Perf event reader started")

	go p.perfEventLoop(rd, em, decoder)
	return nil
}

// perfEventLoop reads events from a perf buffer.
func (p *BaseProbe) perfEventLoop(rd *perf.Reader, em *ebpf.Map, decoder domain.EventDecoder) {
	for {
		select {
		case <-p.ctx.Done():
			p.logger.Debug().Msg("Perf event reader stopping")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if stderrors.Is(err, perf.ErrClosed) {
				return
			}
			p.logger.Warn().Err(err).Msg("Error reading from perf buffer")
			continue
		}

		if record.LostSamples != 0 {
			p.logger.Warn().
				Uint64("lost_samples", record.LostSamples).
				Msg("Perf buffer full, samples lost")
			continue
		}

		event, err := decoder.Decode(em, record.RawSample)
		p.logger.Debug().Str("event", event.String()).Msg("Perf event decoded")
		if err != nil {
			if stderrors.Is(err, errors.ErrEventNotReady) {
				p.logger.Debug().Msg("Event not ready, skipping")
				// Skip incomplete events silently
				continue
			}
			p.logger.Warn().Err(err).Msg("Failed to decode event")
			continue
		}

		if err := p.dispatcher.Dispatch(event); err != nil {
			p.logger.Warn().Err(err).Msg("Failed to dispatch event")
		}
	}
}

// StartRingbufReader starts a ringbuf reader for the given map.
func (p *BaseProbe) StartRingbufReader(em *ebpf.Map, decoder domain.EventDecoder) error {
	if em == nil {
		return errors.New(errors.ErrCodeEBPFMapAccess, "eBPF map cannot be nil")
	}
	if decoder == nil {
		return errors.New(errors.ErrCodeConfiguration, "event decoder cannot be nil")
	}

	rd, err := ringbuf.NewReader(em)
	if err != nil {
		return errors.NewEBPFAttachError(em.String(), err)
	}

	p.readers = append(p.readers, rd)

	p.logger.Info().
		Str("map", em.String()).
		Msg("Ringbuf reader started")

	go p.ringbufEventLoop(rd, em, decoder)
	return nil
}

// ringbufEventLoop reads events from a ringbuf.
func (p *BaseProbe) ringbufEventLoop(rd *ringbuf.Reader, em *ebpf.Map, decoder domain.EventDecoder) {
	for {
		select {
		case <-p.ctx.Done():
			p.logger.Debug().Msg("Ringbuf reader stopping")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if stderrors.Is(err, ringbuf.ErrClosed) {
				return
			}
			p.logger.Warn().Err(err).Msg("Error reading from ringbuf")
			continue
		}

		event, err := decoder.Decode(em, record.RawSample)
		if err != nil {
			p.logger.Warn().Err(err).Msg("Failed to decode event")
			continue
		}

		if err := p.dispatcher.Dispatch(event); err != nil {
			p.logger.Warn().Err(err).Msg("Failed to dispatch event")
		}
	}
}

func (p *BaseProbe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	panic("not implemented")
}
