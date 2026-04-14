// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package gotls

import (
	stderrors "errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// dispatchLogNoReorder is logged immediately before Dispatch in raw perf order (for verify_gotls_reorder_log.py).
const dispatchLogNoReorder = "no reorder"

// dispatchLogAfterReorder is logged immediately before Dispatch after userland reorder.
const dispatchLogAfterReorder = "after reorder"

func logGotlsPerfDispatch(p *Probe, label string, ev *GoTLSDataEvent) {
	p.Logger().Debug().Msg(fmt.Sprintf(
		"gotls perf dispatch (%s) mono_ns=%d emit_cpu=%d seq=%d",
		label, ev.BpfMonoNs, ev.EmitCPU, ev.Seq,
	))
}

// startGoTLSDataPerfReader starts a perf reader for TLS data events with optional userland reorder.
func (p *Probe) startGoTLSDataPerfReader(em *ebpf.Map, decoder domain.EventDecoder) error {
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

	p.TrackPerfReader(rd)

	p.Logger().Info().
		Str("map", em.String()).
		Int("size_mb", mapSize/1024/1024).
		Bool("perf_reorder", p.config.PerfReorder).
		Msg("Perf event reader started (GoTLS)")

	if p.config.PerfReorder {
		p.GoReaderLoop(func() { p.goTLSOrderedPerfLoop(rd, em, decoder) })
	} else {
		p.GoReaderLoop(func() { p.goTLSPlainPerfLoop(rd, em, decoder) })
	}
	return nil
}

func (p *Probe) goTLSPlainPerfLoop(rd *perf.Reader, em *ebpf.Map, decoder domain.EventDecoder) {
	for {
		select {
		case <-p.Context().Done():
			p.Logger().Debug().Msg("GoTLS perf reader stopping")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if stderrors.Is(err, perf.ErrClosed) {
				return
			}
			p.Logger().Warn().Err(err).Msg("Error reading from perf buffer")
			continue
		}
		if record.LostSamples != 0 {
			p.Logger().Warn().
				Uint64("lost_samples", record.LostSamples).
				Msg("Perf buffer full, samples lost")
			continue
		}

		event, err := decoder.Decode(em, record.RawSample)
		if err != nil {
			if stderrors.Is(err, errors.ErrEventNotReady) {
				p.Logger().Debug().Msg("Event not ready, skipping")
				continue
			}
			p.Logger().Warn().Err(err).Msg("Failed to decode event")
			continue
		}
		p.Logger().Debug().Str("event", event.String()).Msg("Perf event decoded")

		gte, ok := event.(*GoTLSDataEvent)
		if !ok {
			if err := p.Dispatcher().Dispatch(event); err != nil {
				p.Logger().Warn().Err(err).Msg("Failed to dispatch event")
			}
			continue
		}
		logGotlsPerfDispatch(p, dispatchLogNoReorder, gte)
		if err := p.Dispatcher().Dispatch(event); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to dispatch GoTLS event")
		}
	}
}

func (p *Probe) goTLSOrderedPerfLoop(rd *perf.Reader, em *ebpf.Map, decoder domain.EventDecoder) {
	reorder := newGoTLSPerfReorder(p.config.PerfReorderLagNs())
	defer func() {
		for _, ev := range reorder.flushAll() {
			logGotlsPerfDispatch(p, dispatchLogAfterReorder, ev)
			if err := p.Dispatcher().Dispatch(ev); err != nil {
				p.Logger().Warn().Err(err).Msg("Failed to dispatch reordered GoTLS event")
			}
		}
	}()

	for {
		select {
		case <-p.Context().Done():
			p.Logger().Debug().Msg("GoTLS perf reader stopping")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if stderrors.Is(err, perf.ErrClosed) {
				return
			}
			p.Logger().Warn().Err(err).Msg("Error reading from perf buffer")
			continue
		}
		if record.LostSamples != 0 {
			p.Logger().Warn().
				Uint64("lost_samples", record.LostSamples).
				Msg("Perf buffer full, samples lost")
			continue
		}

		event, err := decoder.Decode(em, record.RawSample)
		if err != nil {
			if stderrors.Is(err, errors.ErrEventNotReady) {
				p.Logger().Debug().Msg("Event not ready, skipping")
				continue
			}
			p.Logger().Warn().Err(err).Msg("Failed to decode event")
			continue
		}
		p.Logger().Debug().Str("event", event.String()).Msg("Perf event decoded")

		gte, ok := event.(*GoTLSDataEvent)
		if !ok {
			if err := p.Dispatcher().Dispatch(event); err != nil {
				p.Logger().Warn().Err(err).Msg("Failed to dispatch event")
			}
			continue
		}

		for _, ev := range reorder.push(gte) {
			logGotlsPerfDispatch(p, dispatchLogAfterReorder, ev)
			if err := p.Dispatcher().Dispatch(ev); err != nil {
				p.Logger().Warn().Err(err).Msg("Failed to dispatch reordered GoTLS event")
			}
		}
	}
}
