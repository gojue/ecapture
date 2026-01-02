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
	"io"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// TLSDataEvent defines the interface for TLS data events.
type TLSDataEvent interface {
	domain.Event
	GetPid() uint32
	GetComm() string
	GetData() []byte
	GetDataLen() uint32
	GetTimestamp() uint64
	IsRead() bool
}

// TextHandler handles TLS events by formatting them as readable text output.
type TextHandler struct {
	writer io.Writer
}

// NewTextHandler creates a new TextHandler that writes to the provided writer.
func NewTextHandler(writer io.Writer) *TextHandler {
	if writer == nil {
		writer = io.Discard
	}
	return &TextHandler{
		writer: writer,
	}
}

// Handle processes a TLS event and writes formatted text output.
func (h *TextHandler) Handle(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventValidation, "event cannot be nil")
	}

	// Type assert to TLS data event
	tlsEvent, ok := event.(TLSDataEvent)
	if !ok {
		return errors.New(errors.ErrCodeEventValidation, "event is not a TLS data event")
	}

	// Format timestamp
	ts := time.Unix(0, int64(tlsEvent.GetTimestamp()))
	timestamp := ts.Format("2006-01-02 15:04:05.000")

	// Determine direction
	direction := ">>>"
	if tlsEvent.IsRead() {
		direction = "<<<"
	}

	// Format output
	output := fmt.Sprintf("[%s] [PID: %d] [%s] %s\n%s\n",
		timestamp,
		tlsEvent.GetPid(),
		tlsEvent.GetComm(),
		direction,
		string(tlsEvent.GetData()),
	)

	// Write to output
	_, err := h.writer.Write([]byte(output))
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write event", err)
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *TextHandler) Close() error {
	// Check if writer implements io.Closer
	if closer, ok := h.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
