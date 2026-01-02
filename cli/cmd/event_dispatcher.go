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

package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/events"
	"github.com/gojue/ecapture/internal/logger"
)

// stdoutEventHandler prints events to stdout.
type stdoutEventHandler struct {
	useHex bool
	logger *zerolog.Logger
}

// newStdoutEventHandler creates a new stdout event handler.
func newStdoutEventHandler(useHex bool, zlogger *zerolog.Logger) *stdoutEventHandler {
	return &stdoutEventHandler{
		useHex: useHex,
		logger: zlogger,
	}
}

// Handle processes an event by printing it.
func (h *stdoutEventHandler) Handle(event domain.Event) error {
	if event == nil {
		return nil
	}

	var output string
	if h.useHex {
		output = event.StringHex()
	} else {
		output = event.String()
	}

	if output != "" {
		if h.logger != nil {
			h.logger.Info().Msg(output)
		} else {
			fmt.Println(output)
		}
	}

	return nil
}

// Name returns the handler's identifier.
func (h *stdoutEventHandler) Name() string {
	return "stdout"
}

// newEventDispatcher creates an event dispatcher with stdout handler.
// This is used when logger is not available (deprecated).
func newEventDispatcher(useHex bool) (domain.EventDispatcher, error) {
	// Create logger
	log := logger.New(os.Stdout, false)

	// Create dispatcher
	dispatcher := events.NewDispatcher(log)

	// Register stdout handler
	handler := newStdoutEventHandler(useHex, nil)
	if err := dispatcher.Register(handler); err != nil {
		return nil, fmt.Errorf("failed to register stdout handler: %w", err)
	}

	return dispatcher, nil
}

// newEventDispatcherWithLogger creates an event dispatcher with logger support.
func newEventDispatcherWithLogger(zlogger *zerolog.Logger, useHex bool) (domain.EventDispatcher, error) {
	// Create internal logger wrapper from zerolog
	log := logger.New(os.Stdout, false)

	// Create dispatcher
	dispatcher := events.NewDispatcher(log)

	// Register stdout handler with logger
	handler := newStdoutEventHandler(useHex, zlogger)
	if err := dispatcher.Register(handler); err != nil {
		return nil, fmt.Errorf("failed to register stdout handler: %w", err)
	}

	return dispatcher, nil
}
