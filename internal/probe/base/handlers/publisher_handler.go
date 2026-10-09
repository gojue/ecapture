// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package handlers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/output/writers"
)

// PublisherHandler forwards typed domain events in parallel with raw artifact
// handlers. It borrows the publisher; the process runtime owns and closes it.
type PublisherHandler struct {
	sink     domain.CapturedEventSink
	format   domain.CaptureFormat
	useHex   bool
	mu       sync.Mutex
	closed   bool
	sequence uint64
}

func NewPublisherHandler(sink domain.CapturedEventSink, format domain.CaptureFormat, useHex bool) (*PublisherHandler, error) {
	if sink == nil {
		return nil, fmt.Errorf("captured event sink cannot be nil")
	}
	switch format {
	case domain.CaptureFormatText, domain.CaptureFormatKeylog, domain.CaptureFormatPcapng:
	default:
		return nil, fmt.Errorf("unsupported capture format %q", format)
	}
	return &PublisherHandler{sink: sink, format: format, useHex: useHex}, nil
}

func (h *PublisherHandler) Supports(event domain.Event) bool {
	switch h.format {
	case domain.CaptureFormatText:
		return event != nil && event.Type() == domain.EventTypeOutput &&
			!isSecretEvent(event) && !isPacketEvent(event)
	case domain.CaptureFormatKeylog:
		return isSecretEvent(event)
	case domain.CaptureFormatPcapng:
		return isPacketEvent(event)
	default:
		return false
	}
}

func (h *PublisherHandler) Handle(event domain.Event) error {
	if !h.Supports(event) {
		return errors.New(errors.ErrCodeEventDispatch, "publisher handler does not support event")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New(errors.ErrCodeEventDispatch, "publisher handler is closed")
	}
	h.sequence++
	envelope := h.envelope(event, h.sequence)
	if err := h.sink.PublishEvent(context.Background(), envelope); err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to publish captured event", err)
	}
	return nil
}

func (h *PublisherHandler) envelope(event domain.Event, sequence uint64) domain.CapturedEventEnvelope {
	envelope := domain.CapturedEventEnvelope{
		Timestamp:   time.Now(),
		UUID:        event.UUID(),
		EventType:   event.Type(),
		Format:      h.format,
		Sensitivity: domain.SensitivityNormal,
		Sequence:    sequence,
		DomainEvent: event,
	}
	if h.format == domain.CaptureFormatKeylog || h.format == domain.CaptureFormatPcapng {
		envelope.Sensitivity = domain.SensitivitySensitive
	}
	if value, ok := event.(interface{ GetTimestampTime() time.Time }); ok {
		if timestamp := value.GetTimestampTime(); !timestamp.IsZero() {
			envelope.Timestamp = timestamp
		}
	} else if value, ok := event.(interface{ GetTimestamp() time.Time }); ok {
		if timestamp := value.GetTimestamp(); !timestamp.IsZero() {
			envelope.Timestamp = timestamp
		}
	} else if value, ok := event.(interface{ GetTimestamp() uint64 }); ok {
		if timestamp := value.GetTimestamp(); timestamp != 0 {
			envelope.Timestamp = time.Unix(0, int64(timestamp))
		}
	}
	if value, ok := event.(interface{ GetPid() uint32 }); ok {
		envelope.PID = uint64(value.GetPid())
	}
	if value, ok := event.(interface{ GetComm() string }); ok {
		envelope.ProcessName = value.GetComm()
	}
	if value, ok := event.(interface{ GetData() []byte }); ok {
		envelope.Payload = append([]byte(nil), value.GetData()...)
	}
	if value, ok := event.(interface{ GetDataLen() uint32 }); ok {
		envelope.OriginalLength = value.GetDataLen()
	}
	if packet, ok := event.(PacketEvent); ok {
		envelope.Payload = append([]byte(nil), packet.GetPacketData()...)
		envelope.OriginalLength = packet.GetPacketLen()
		envelope.SourceIP = packet.GetSrcIP()
		envelope.SourcePort = uint32(packet.GetSrcPort())
		envelope.DestinationIP = packet.GetDstIP()
		envelope.DestinationPort = uint32(packet.GetDstPort())
	}
	if value, ok := event.(interface{ GetSrcIP() string }); ok {
		envelope.SourceIP = value.GetSrcIP()
	}
	if value, ok := event.(interface{ GetSrcPort() uint16 }); ok {
		envelope.SourcePort = uint32(value.GetSrcPort())
	}
	if value, ok := event.(interface{ GetDstIP() string }); ok {
		envelope.DestinationIP = value.GetDstIP()
	}
	if value, ok := event.(interface{ GetDstPort() uint16 }); ok {
		envelope.DestinationPort = uint32(value.GetDstPort())
	}
	if value, ok := event.(interface{ IsRead() bool }); ok {
		if value.IsRead() {
			envelope.Direction = "read"
		} else {
			envelope.Direction = "write"
		}
	}
	if len(envelope.Payload) == 0 {
		if h.useHex && h.format == domain.CaptureFormatText {
			envelope.Payload = []byte(event.StringHex())
		} else {
			envelope.Payload = []byte(event.String())
		}
	}
	if envelope.OriginalLength == 0 {
		envelope.OriginalLength = uint32(len(envelope.Payload))
	}
	return envelope
}

func (h *PublisherHandler) Name() string {
	return fmt.Sprintf("publisher-%s-%s", h.format, h.sink.Name())
}

func (h *PublisherHandler) Writer() writers.OutputWriter { return nil }

func (h *PublisherHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	return nil
}

var _ domain.EventHandler = (*PublisherHandler)(nil)
