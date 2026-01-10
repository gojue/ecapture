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
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/output/encoders"
	"github.com/gojue/ecapture/internal/output/writers"
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
// It uses OutputWriter for destination and Encoder for format.
type TextHandler struct {
	writer  writers.OutputWriter
	encoder encoders.Encoder
	useHex  bool
}

// NewTextHandler creates a new TextHandler with the provided writer and encoder.
func NewTextHandler(writer writers.OutputWriter, encoder encoders.Encoder, useHex bool) *TextHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
	}
	if encoder == nil {
		encoder = encoders.NewPlainEncoder(useHex)
	}
	return &TextHandler{
		writer:  writer,
		encoder: encoder,
		useHex:  useHex,
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
		// Not a TLS data event, skip silently (other handlers will process it)
		return nil
	}

	// Format using custom text format (not encoder, as this is TLS-specific formatting)
	// Format timestamp
	ts := time.Unix(0, int64(tlsEvent.GetTimestamp()))
	timestamp := ts.Format("2006-01-02 15:04:05.000")

	// Determine direction
	direction := ">>>"
	if tlsEvent.IsRead() {
		direction = "<<<"
	}

	// Format data based on hex mode
	var dataOutput string
	data := tlsEvent.GetData()
	if h.useHex {
		// Hex mode: format as hexadecimal
		dataOutput = hex.Dump(data)
	} else {
		// Text mode: convert to string (may contain non-ASCII characters)
		dataOutput = string(data)
	}

	// Format output
	output := fmt.Sprintf("[%s] [PID: %d] [%s] %s\n%s\n",
		timestamp,
		tlsEvent.GetPid(),
		tlsEvent.GetComm(),
		direction,
		dataOutput,
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
	if h.writer != nil {
		return h.writer.Close()
	}
	return nil
}

// Name returns the handler's identifier.
func (h *TextHandler) Name() string {
	return ModeText
}
