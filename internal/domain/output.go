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

package domain

import (
	"context"
	"time"
)

// CaptureFormat identifies an event representation without selecting its
// destination.
type CaptureFormat string

const (
	CaptureFormatText   CaptureFormat = "text"
	CaptureFormatKeylog CaptureFormat = "keylog"
	CaptureFormatPcapng CaptureFormat = "pcapng"
)

// Sensitivity classifies data before it reaches a destination.
type Sensitivity string

const (
	SensitivityNormal    Sensitivity = "normal"
	SensitivitySensitive Sensitivity = "sensitive"
)

// OperationalLogRecord is a typed eCapture runtime record. Message contains
// the representation emitted by the logging edge; captured payloads and TLS
// secrets must never be placed in this type.
type OperationalLogRecord struct {
	Timestamp time.Time
	Level     string
	Message   string
}

// CapturedEventEnvelope carries a domain event and its available metadata to a
// typed publisher. DomainEvent is intentionally excluded from serialized
// configuration and lets publishers consume the event without reverse-parsing
// text, keylog, or pcapng bytes.
type CapturedEventEnvelope struct {
	Timestamp       time.Time
	UUID            string
	EventType       EventType
	Format          CaptureFormat
	Sensitivity     Sensitivity
	PID             uint64
	ProcessName     string
	SourceIP        string
	SourcePort      uint32
	DestinationIP   string
	DestinationPort uint32
	Direction       string
	Payload         []byte
	OriginalLength  uint32
	StreamID        string
	Sequence        uint64
	DomainEvent     Event
}

// OperationalLogSink publishes typed eCapture runtime records. It is not a
// ByteSink; an io.Writer adapter may be used only at the logging-library edge.
type OperationalLogSink interface {
	PublishLog(context.Context, OperationalLogRecord) error
	Name() string
	Close() error
}

// CapturedEventSink publishes typed captured events independently of any raw
// text, keylog, or pcapng ByteSink.
type CapturedEventSink interface {
	PublishEvent(context.Context, CapturedEventEnvelope) error
	Name() string
	Close() error
}
