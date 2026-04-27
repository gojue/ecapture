// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package base

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/domain"
)

type fakePerfEvent struct {
	mono    uint64
	payload byte
}

func (e *fakePerfEvent) DecodeFromBytes(_ []byte) error { return nil }
func (e *fakePerfEvent) String() string                 { return string(e.payload) }
func (e *fakePerfEvent) StringHex() string              { return fmt.Sprintf("%x", e.payload) }
func (e *fakePerfEvent) Clone() domain.Event            { return &fakePerfEvent{} }
func (e *fakePerfEvent) Type() domain.EventType         { return domain.EventTypeOutput }
func (e *fakePerfEvent) UUID() string                   { return string(e.payload) }
func (e *fakePerfEvent) Validate() error                { return nil }
func (e *fakePerfEvent) PerfMonoNs() uint64             { return e.mono }

type fakePlainEvent struct{}

func (e *fakePlainEvent) DecodeFromBytes(_ []byte) error { return nil }
func (e *fakePlainEvent) String() string                 { return "plain" }
func (e *fakePlainEvent) StringHex() string              { return "plain" }
func (e *fakePlainEvent) Clone() domain.Event            { return &fakePlainEvent{} }
func (e *fakePlainEvent) Type() domain.EventType         { return domain.EventTypeOutput }
func (e *fakePlainEvent) UUID() string                   { return "plain" }
func (e *fakePlainEvent) Validate() error                { return nil }

type fakeDecoder struct {
	prototype domain.Event
	ok        bool
}

func (d fakeDecoder) Decode(_ *ebpf.Map, _ []byte) (domain.Event, error) {
	return d.prototype, nil
}

func (d fakeDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return d.prototype, d.ok
}

func ev(mono uint64, payload byte) *fakePerfEvent {
	return &fakePerfEvent{mono: mono, payload: payload}
}

func TestPerfLagReorder_flushByLag_ordersWithinCutoff(t *testing.T) {
	r := newPerfLagReorder(10)
	_ = r.push(ev(100, 'b'))
	out := r.push(ev(50, 'a'))
	if len(out) != 1 {
		t.Fatalf("want 1 flushed (older mono), got %d", len(out))
	}
	if out[0].(*fakePerfEvent).payload != 'a' {
		t.Fatalf("expected payload a, got %q", out[0].String())
	}
	out = r.push(ev(120, 'c'))
	if len(out) != 1 || out[0].(*fakePerfEvent).payload != 'b' {
		t.Fatalf("expected b flush, got %v", out)
	}
	rest := r.flushAll()
	if len(rest) != 1 || rest[0].(*fakePerfEvent).payload != 'c' {
		t.Fatalf("remainder: %+v", rest)
	}
}

func TestPerfLagReorder_flushAll_ordersRemainder(t *testing.T) {
	r := newPerfLagReorder(100)
	_ = r.push(ev(30, 'c'))
	_ = r.push(ev(10, 'a'))
	_ = r.push(ev(20, 'b'))

	out := r.flushAll()
	if got := string([]byte{
		out[0].(*fakePerfEvent).payload,
		out[1].(*fakePerfEvent).payload,
		out[2].(*fakePerfEvent).payload,
	}); got != "abc" {
		t.Fatalf("flushAll order = %q, want abc", got)
	}
}

func TestBaseProbe_decoderSupportsPerfReorder(t *testing.T) {
	tests := []struct {
		name        string
		decoder     domain.EventDecoder
		wantEnabled bool
	}{
		{
			name:        "mono event",
			decoder:     fakeDecoder{prototype: ev(1, 'x'), ok: true},
			wantEnabled: true,
		},
		{
			name:        "plain event",
			decoder:     fakeDecoder{prototype: &fakePlainEvent{}, ok: true},
			wantEnabled: false,
		},
		{
			name:        "missing decoder prototype",
			decoder:     fakeDecoder{prototype: nil, ok: false},
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BaseProbe{}
			enabled := p.decoderSupportsPerfReorder(nil, tt.decoder)
			if enabled != tt.wantEnabled {
				t.Fatalf("enabled = %v, want %v", enabled, tt.wantEnabled)
			}
		})
	}
}

func TestBaseConfig_GetPerfReorder(t *testing.T) {
	cfg := &config.BaseConfig{
		PerCpuMapSize:    config.DefaultMapSizePerCpu,
		PerfReorder:      true,
		PerfReorderLagMs: 20,
		ByteCodeFileMode: config.ByteCodeFileAll,
		BtfMode:          config.BTFModeAutoDetect,
	}

	enabled, lagNs := cfg.GetPerfReorder()
	if !enabled {
		t.Fatal("GetPerfReorder enabled = false, want true")
	}
	if lagNs != 20_000_000 {
		t.Fatalf("GetPerfReorder lagNs = %d, want 20000000", lagNs)
	}

	cfg.PerfReorder = false
	enabled, lagNs = cfg.GetPerfReorder()
	if enabled || lagNs != 0 {
		t.Fatalf("GetPerfReorder disabled = (%v, %d), want (false, 0)", enabled, lagNs)
	}
}
