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

// EventType defines the category of an event.
type EventType uint8

const (
	// EventTypeOutput indicates events that should be written to output.
	EventTypeOutput EventType = iota

	// EventTypeModuleData indicates events stored as module cache data.
	EventTypeModuleData

	// EventTypeProcessor indicates events processed by the event processor.
	EventTypeProcessor
)

// Event defines the interface for all events captured by probes.
type Event interface {
	// DecodeFromBytes deserializes the event from raw bytes.
	DecodeFromBytes(data []byte) error

	// String returns a human-readable representation of the event.
	String() string

	// StringHex returns a hexadecimal representation of the event.
	StringHex() string

	// Clone creates a deep copy of the event.
	Clone() Event

	// Type returns the category of this event.
	Type() EventType

	// UUID returns a unique identifier for this event.
	UUID() string

	// Validate checks if the event data is valid.
	Validate() error
}

// EventHandler processes events after they are decoded.
type EventHandler interface {
	// Handle processes a decoded event.
	Handle(event Event) error

	// Name returns the handler's identifier.
	Name() string
}

// EventDispatcher manages event distribution to registered handlers.
type EventDispatcher interface {
	// Register adds an event handler to the dispatcher.
	Register(handler EventHandler) error

	// Unregister removes an event handler from the dispatcher.
	Unregister(handlerName string) error

	// Dispatch sends an event to all registered handlers.
	Dispatch(event Event) error

	// Close stops the dispatcher and releases resources.
	Close() error
}
