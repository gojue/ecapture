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

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/events"
	"github.com/gojue/ecapture/internal/logger"
)

// stdoutEventHandler prints events to stdout.
type stdoutEventHandler struct {
	useHex bool
}

// newStdoutEventHandler creates a new stdout event handler.
func newStdoutEventHandler(useHex bool) *stdoutEventHandler {
	return &stdoutEventHandler{
		useHex: useHex,
	}
}

// Handle processes an event by printing it to stdout.
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
		fmt.Println(output)
	}

	return nil
}

// Name returns the handler's identifier.
func (h *stdoutEventHandler) Name() string {
	return "stdout"
}

// newEventDispatcher creates an event dispatcher with stdout handler.
func newEventDispatcher(useHex bool) (domain.EventDispatcher, error) {
	// Create logger
	log := logger.New(os.Stdout, globalConf.Debug)

	// Create dispatcher
	dispatcher := events.NewDispatcher(log)

	// Register stdout handler
	handler := newStdoutEventHandler(useHex)
	if err := dispatcher.Register(handler); err != nil {
		return nil, fmt.Errorf("failed to register stdout handler: %w", err)
	}

	return dispatcher, nil
}
