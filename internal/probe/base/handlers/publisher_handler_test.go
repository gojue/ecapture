// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"context"
	"sync"
	"testing"

	"github.com/gojue/ecapture/v2/internal/domain"
)

type recordingEventPublisher struct {
	mu         sync.Mutex
	events     []domain.CapturedEventEnvelope
	closeCalls int
}

func (p *recordingEventPublisher) PublishEvent(_ context.Context, event domain.CapturedEventEnvelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	event.Payload = append([]byte(nil), event.Payload...)
	p.events = append(p.events, event)
	return nil
}

func (p *recordingEventPublisher) Name() string { return "recording" }

func (p *recordingEventPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeCalls++
	return nil
}

func (p *recordingEventPublisher) last(t *testing.T) domain.CapturedEventEnvelope {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.events) == 0 {
		t.Fatal("publisher received no events")
	}
	return p.events[len(p.events)-1]
}

func TestPublisherHandlerRoutesTypedFormats(t *testing.T) {
	tests := []struct {
		name        string
		format      domain.CaptureFormat
		event       domain.Event
		sensitivity domain.Sensitivity
		payload     []byte
	}{
		{
			name:        "text",
			format:      domain.CaptureFormatText,
			event:       &mockTLSDataEvent{pid: 42, comm: "curl", data: []byte("captured-payload"), dataLen: 16, timestamp: 123, isRead: true},
			sensitivity: domain.SensitivityNormal,
			payload:     []byte("captured-payload"),
		},
		{
			name:        "keylog",
			format:      domain.CaptureFormatKeylog,
			event:       &mockMasterSecretEvent{version: 0x0303, clientRandom: make([]byte, 32), masterKey: make([]byte, 48)},
			sensitivity: domain.SensitivitySensitive,
		},
		{
			name:        "pcapng packet row",
			format:      domain.CaptureFormatPcapng,
			event:       &mockPacketEvent{timestamp: 456, packetData: []byte{1, 2, 3}, packetLen: 3, srcIP: "127.0.0.1", dstIP: "127.0.0.2", srcPort: 1234, dstPort: 443},
			sensitivity: domain.SensitivitySensitive,
			payload:     []byte{1, 2, 3},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publisher := &recordingEventPublisher{}
			handler, err := NewPublisherHandler(publisher, test.format, false)
			if err != nil {
				t.Fatal(err)
			}
			if !handler.Supports(test.event) {
				t.Fatalf("handler does not support %T", test.event)
			}
			if err = handler.Handle(test.event); err != nil {
				t.Fatal(err)
			}
			envelope := publisher.last(t)
			if envelope.DomainEvent != test.event {
				t.Fatal("publisher did not receive the original domain event")
			}
			if envelope.Format != test.format || envelope.Sensitivity != test.sensitivity {
				t.Fatalf("metadata = (%s, %s)", envelope.Format, envelope.Sensitivity)
			}
			if test.payload != nil && string(envelope.Payload) != string(test.payload) {
				t.Fatalf("payload = %q, want %q", envelope.Payload, test.payload)
			}
			if err = handler.Close(); err != nil {
				t.Fatal(err)
			}
			if publisher.closeCalls != 0 {
				t.Fatal("borrowed publisher was closed by handler")
			}
		})
	}
}

func TestPcapPublisherDoesNotPublishDSBSecretEvents(t *testing.T) {
	publisher := &recordingEventPublisher{}
	handler, err := NewPublisherHandler(publisher, domain.CaptureFormatPcapng, false)
	if err != nil {
		t.Fatal(err)
	}
	secret := &mockMasterSecretEvent{version: 0x0303}
	if handler.Supports(secret) {
		t.Fatal("pcapng publisher must not publish DSB-only secret events")
	}
	if err = handler.Handle(secret); err == nil {
		t.Fatal("direct Handle should reject a DSB-only secret event")
	}
}
