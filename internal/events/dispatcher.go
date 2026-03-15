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

package events

import (
	"fmt"
	"sync"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/logger"
)

// Dispatcher implements the Observer pattern for event distribution.
type Dispatcher struct {
	handlers map[string]domain.EventHandler
	mu       sync.RWMutex
	logger   *logger.Logger
	closed   bool
}

// NewDispatcher creates a new event dispatcher.
func NewDispatcher(log *logger.Logger) *Dispatcher {
	return &Dispatcher{
		handlers: make(map[string]domain.EventHandler),
		logger:   log,
		closed:   false,
	}
}

// Register adds an event handler to the dispatcher.
func (d *Dispatcher) Register(handler domain.EventHandler) error {
	if handler == nil {
		return errors.New(errors.ErrCodeConfiguration, "handler cannot be nil")
	}
	d.logger.Debug().Str("event-handler", handler.Name()).Msg("### event handler registered")

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return errors.New(errors.ErrCodeConfiguration, "dispatcher is closed")
	}

	name := fmt.Sprintf("%s-%s", handler.Name(), handler.Writer().Name())
	if _, exists := d.handlers[name]; exists {
		return errors.New(errors.ErrCodeConfiguration, "handler already registered").
			WithContext("handler", name)
	}

	d.handlers[name] = handler
	d.logger.Debug().
		Str("handler", name).
		Msg("Event handler registered")

	return nil
}

// Unregister removes an event handler from the dispatcher.
func (d *Dispatcher) Unregister(handlerName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return errors.New(errors.ErrCodeConfiguration, "dispatcher is closed")
	}

	if _, exists := d.handlers[handlerName]; !exists {
		return errors.NewResourceNotFoundError("handler: " + handlerName)
	}

	delete(d.handlers, handlerName)
	d.logger.Debug().
		Str("handler", handlerName).
		Msg("Event handler unregistered")

	return nil
}

// Dispatch sends an event to all registered handlers.
func (d *Dispatcher) Dispatch(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventDispatch, "event cannot be nil")
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return errors.New(errors.ErrCodeEventDispatch, "dispatcher is closed")
	}

	// Validate event before dispatching
	if err := event.Validate(); err != nil {
		return errors.Wrap(errors.ErrCodeEventValidation, "invalid event", err)
	}

	var lastErr error
	var count int
	for name, handler := range d.handlers {
		if err := handler.Handle(event); err != nil {
			d.logger.Debug().
				Err(err).
				Str("handler", name).
				Msg("Handler failed to process event")
			lastErr = err
		} else {
			lastErr = nil
			count++
		}
	}

	// 一个都没成功
	if count == 0 && lastErr != nil {
		d.logger.Error().Err(lastErr).Str("event", event.String()).Msg("Event handler failed to process event")
		return lastErr
	}
	return nil
}

// Close stops the dispatcher and releases resources.
func (d *Dispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true

	// Close all handlers that implement io.Closer interface
	var closeErrors []error
	for name, handler := range d.handlers {
		if closer, ok := handler.(interface{ Close() error }); ok {
			d.logger.Debug().Str("handler", name).Msg("Closing handler")
			if err := closer.Close(); err != nil {
				d.logger.Debug().
					Err(err).
					Str("handler", name).
					Msg("Failed to close handler")
				closeErrors = append(closeErrors, err)
			} else {
				d.logger.Info().Str("handler", name).Msg("Handler closed successfully")
			}
		}
	}

	d.handlers = nil

	d.logger.Info().Msg("Event dispatcher closed")

	// Return the first error if any occurred
	if len(closeErrors) > 0 {
		return closeErrors[0]
	}
	return nil
}

// HandlerCount returns the number of registered handlers.
func (d *Dispatcher) HandlerCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.handlers)
}
