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

package handlers

import (
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/output/writers"
	"github.com/gojue/ecapture/pkg/event_processor"
)

// ProcessorHandler handles events by routing TLS data events through
// the event_processor for protocol detection (HTTP, HTTP/2, etc.),
// while passing non-TLS events directly to the writer via String().
//
// This follows the v1.x architecture where:
// - internal/ code only does raw TLS decryption (Event.String() = string(data))
// - pkg/event_processor does protocol type guessing and formatted output
type ProcessorHandler struct {
	writer    writers.OutputWriter
	processor *event_processor.EventProcessor
	useHex    bool
	errChan   chan error
}

// NewProcessorHandler creates a new ProcessorHandler.
// It creates an EventProcessor that writes formatted output to the writer,
// and starts the processor's background Serve goroutine.
func NewProcessorHandler(writer writers.OutputWriter, useHex bool, truncateSize uint64) *ProcessorHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
	}

	// Create the event processor with the writer as its output target.
	// The processor's Serve() goroutine will write formatted data to this writer.
	processor := event_processor.NewEventProcessor(writer, useHex, truncateSize)

	h := &ProcessorHandler{
		writer:    writer,
		processor: processor,
		useHex:    useHex,
		errChan:   make(chan error, 16),
	}

	// Start the processor's event loop in background
	go func() {
		if err := processor.Serve(); err != nil {
			select {
			case h.errChan <- err:
			default:
			}
		}
	}()

	// Drain processor errors in background
	go func() {
		for range processor.ErrorChan() {
			// Log or discard processor errors silently
		}
	}()

	return h
}

// Handle processes an event. TLS data events (those implementing
// event_processor.TLSDataProvider) are forwarded to the event_processor
// for protocol detection. Other events are written directly via String().
func (h *ProcessorHandler) Handle(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventValidation, "event cannot be nil")
	}

	// Check if this is a TLS data event that should go through event_processor
	if provider, ok := event.(event_processor.TLSDataProvider); ok {
		return h.handleTLSDataEvent(event, provider)
	}

	// Non-TLS events: direct output via String()/StringHex() (same as TextHandler)
	return h.handleDirectEvent(event)
}

// handleTLSDataEvent adapts the event and sends it to the event_processor.
func (h *ProcessorHandler) handleTLSDataEvent(event domain.Event, provider event_processor.TLSDataProvider) error {
	uuid := event.UUID()
	adapted := event_processor.NewDomainEventAdapter(provider, uuid)
	h.processor.Write(adapted)
	return nil
}

// handleDirectEvent writes non-TLS events directly to the writer.
func (h *ProcessorHandler) handleDirectEvent(event domain.Event) error {
	var output string
	if h.useHex {
		type hexStringer interface {
			StringHex() string
		}
		if hs, ok := event.(hexStringer); ok {
			output = hs.StringHex()
		} else {
			output = event.String()
		}
	} else {
		output = event.String()
	}

	if output == "" {
		return nil
	}

	if output[len(output)-1] != '\n' {
		output += "\n"
	}

	_, err := h.writer.Write([]byte(output))
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write event output", err)
	}
	return nil
}

// Close closes the handler and releases resources.
func (h *ProcessorHandler) Close() error {
	var firstErr error
	if h.processor != nil {
		if err := h.processor.Close(); err != nil {
			firstErr = err
		}
	}
	if h.writer != nil {
		if err := h.writer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Name returns the handler's identifier.
func (h *ProcessorHandler) Name() string {
	return ModeText
}

// Writer returns the associated output writer.
func (h *ProcessorHandler) Writer() writers.OutputWriter {
	return h.writer
}
