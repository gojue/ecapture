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

package event_processor

import (
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// TLSDataProvider is the interface that TLS data events from internal/probe/
// must implement so they can be adapted for use with the EventProcessor.
type TLSDataProvider interface {
	GetData() []byte
	GetPid() uint32
	GetComm() string
}

// DomainEventAdapter adapts a domain.Event that carries TLS payload data
// into the event_processor.IEventStruct interface so it can be processed
// by EventProcessor for protocol detection (HTTP, HTTP/2, etc.).
type DomainEventAdapter struct {
	uuid    string
	payload []byte
	base    Base
}

// NewDomainEventAdapter creates an adapter from a TLSDataProvider.
// The uuid parameter should uniquely identify the logical connection or event stream.
func NewDomainEventAdapter(provider TLSDataProvider, uuid string) *DomainEventAdapter {
	return &DomainEventAdapter{
		uuid:    uuid,
		payload: provider.GetData(),
		base: Base{
			PID:   int64(provider.GetPid()),
			PName: provider.GetComm(),
			UUID:  uuid,
		},
	}
}

func (a *DomainEventAdapter) GetUUID() string {
	return a.uuid
}

func (a *DomainEventAdapter) Payload() []byte {
	return a.payload
}

func (a *DomainEventAdapter) Base() Base {
	return a.base
}

func (a *DomainEventAdapter) ToProtobufEvent() *pb.Event {
	return &pb.Event{
		Uuid:  a.uuid,
		Pid:   a.base.PID,
		Pname: a.base.PName,
	}
}

func (a *DomainEventAdapter) Clone() IEventStruct {
	clone := *a
	p := make([]byte, len(a.payload))
	copy(p, a.payload)
	clone.payload = p
	return &clone
}

func (a *DomainEventAdapter) EventType() Type {
	return TypeEventProcessor
}

// FormatTLSData runs the event_processor parser detection on the given
// raw TLS payload and returns the formatted output. This is a convenience
// function that applies protocol detection (HTTP/1, HTTP/2, etc.) to a
// single payload without the full EventProcessor worker pipeline.
func FormatTLSData(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	parser := NewParser(payload)
	_, _ = parser.Write(payload)
	b := parser.Display()
	if len(b) == 0 {
		return payload
	}
	return b
}


