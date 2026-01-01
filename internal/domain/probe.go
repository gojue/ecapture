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

package domain

import (
	"context"

	"github.com/cilium/ebpf"
)

// Probe defines the interface for all eBPF probes in eCapture.
// Each probe implementation must support initialization, lifecycle management,
// and event processing.
type Probe interface {
	// Initialize sets up the probe with the provided context, configuration, and event dispatcher.
	// It prepares all necessary resources but does not start the probe.
	Initialize(ctx context.Context, config Configuration, dispatcher EventDispatcher) error

	// Start begins the probe's operation, attaching eBPF programs and starting event collection.
	Start(ctx context.Context) error

	// Stop gracefully halts the probe's operation without releasing resources.
	Stop(ctx context.Context) error

	// Close releases all resources held by the probe.
	// This should be called after Stop to ensure clean shutdown.
	Close() error

	// Name returns the unique identifier for this probe.
	Name() string

	// IsRunning returns true if the probe is currently active.
	IsRunning() bool

	// Events returns the eBPF maps used for event collection.
	Events() []*ebpf.Map
}

// EventDecoder defines the interface for decoding events from eBPF maps.
type EventDecoder interface {
	// Decode deserializes raw bytes from an eBPF map into an Event.
	Decode(em *ebpf.Map, data []byte) (Event, error)

	// GetDecoder returns the event decoder for a specific eBPF map.
	GetDecoder(em *ebpf.Map) (Event, bool)
}
