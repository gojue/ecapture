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
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/output/writers"
)

// TLSDataEvent defines the interface for TLS payload data events.
// Events that carry TLS payload data (reads and writes) implement this interface.
type TLSDataEvent interface {
	domain.Event
	GetPid() uint32
	GetComm() string
	GetData() []byte
	GetDataLen() uint32
	GetTimestamp() uint64
	IsRead() bool
}

// TextHandler handles events by writing their encoded output to a destination.
// It delegates formatting to the event itself via String() or StringHex() methods.
type TextHandler struct {
	writer writers.OutputWriter
	useHex bool
}

func (h *TextHandler) Writer() writers.OutputWriter {
	return h.writer
}

// NewTextHandler creates a new TextHandler with the provided writer.
// Events format themselves via String() or StringHex() methods.
func NewTextHandler(writer writers.OutputWriter, useHex bool) *TextHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
	}
	return &TextHandler{
		writer: writer,
		useHex: useHex,
	}
}

// Handle processes an event and writes its formatted output.
// TLSDataEvents are formatted with PID, comm, direction and payload.
// Other event types are skipped silently.
func (h *TextHandler) Handle(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventValidation, "event cannot be nil")
	}

	// Check if the event carries TLS payload data
	tlsEvent, ok := event.(TLSDataEvent)
	if !ok {
		// Not a TLS data event – skip silently so other handlers can process it
		return nil
	}

	direction := ">>>"
	if tlsEvent.IsRead() {
		direction = "<<<"
	}

	var payload string
	if h.useHex {
		payload = fmt.Sprintf("%x", tlsEvent.GetData())
	} else {
		payload = string(tlsEvent.GetData())
	}

	output := fmt.Sprintf("PID: %d COMM: %s %s\n%s\n",
		tlsEvent.GetPid(),
		tlsEvent.GetComm(),
		direction,
		payload,
	)

	// Write to output destination
	_, err := h.writer.Write([]byte(output))
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write event output", err)
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *TextHandler) Close() error {
	if h.writer != nil {
		return h.writer.Close()
	}
	return nil
}

// Name returns the handler's identifier.
func (h *TextHandler) Name() string {
	return ModeText
}
