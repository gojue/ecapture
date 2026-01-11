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
	"errors"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/logger"
)

// mockEvent implements domain.Event for testing
type mockEvent struct {
	valid bool
}

func (m *mockEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *mockEvent) String() string                    { return "mock" }
func (m *mockEvent) StringHex() string                 { return "mock" }
func (m *mockEvent) Clone() domain.Event               { return &mockEvent{valid: m.valid} }
func (m *mockEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (m *mockEvent) UUID() string                      { return "test-uuid" }
func (m *mockEvent) Validate() error {
	if !m.valid {
		return errors.New("invalid event")
	}
	return nil
}

// mockHandler implements domain.EventHandler for testing
type mockHandler struct {
	name       string
	handleFunc func(event domain.Event) error
}

func (m *mockHandler) Writer() writers.writers {
	//TODO implement me
	panic("implement me")
}

func (m *mockHandler) Name() string { return m.name }
func (m *mockHandler) Handle(event domain.Event) error {
	if m.handleFunc != nil {
		return m.handleFunc(event)
	}
	return nil
}

func TestNewDispatcher(t *testing.T) {
	log := logger.New(nil, false)
	disp := NewDispatcher(log)

	if disp == nil {
		t.Fatal("NewDispatcher returned nil")
		return
	}
	if disp.HandlerCount() != 0 {
		t.Errorf("expected 0 handlers, got %d", disp.HandlerCount())
	}
}

func TestDispatcherRegister(t *testing.T) {
	log := logger.New(nil, false)
	disp := NewDispatcher(log)

	handler := &mockHandler{name: "test-handler"}
	err := disp.Register(handler)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if disp.HandlerCount() != 1 {
		t.Errorf("expected 1 handler, got %d", disp.HandlerCount())
	}
}

func TestDispatcherRegisterDuplicate(t *testing.T) {
	log := logger.New(nil, false)
	disp := NewDispatcher(log)

	handler := &mockHandler{name: "test-handler"}
	_ = disp.Register(handler)

	err := disp.Register(handler)
	if err == nil {
		t.Error("Register() should return error for duplicate handler")
	}
}

func TestDispatcherUnregister(t *testing.T) {
	log := logger.New(nil, false)
	disp := NewDispatcher(log)

	handler := &mockHandler{name: "test-handler"}
	_ = disp.Register(handler)

	err := disp.Unregister("test-handler")
	if err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}

	if disp.HandlerCount() != 0 {
		t.Errorf("expected 0 handlers, got %d", disp.HandlerCount())
	}
}

func TestDispatcherDispatch(t *testing.T) {
	log := logger.New(nil, false)
	disp := NewDispatcher(log)

	called := false
	handler := &mockHandler{
		name: "test-handler",
		handleFunc: func(event domain.Event) error {
			called = true
			return nil
		},
	}
	_ = disp.Register(handler)

	event := &mockEvent{valid: true}
	err := disp.Dispatch(event)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	if !called {
		t.Error("handler was not called")
	}
}

func TestDispatcherDispatchInvalidEvent(t *testing.T) {
	log := logger.New(nil, false)
	disp := NewDispatcher(log)

	handler := &mockHandler{name: "test-handler"}
	_ = disp.Register(handler)

	event := &mockEvent{valid: false}
	err := disp.Dispatch(event)
	if err == nil {
		t.Error("Dispatch() should return error for invalid event")
	}
}

func TestDispatcherClose(t *testing.T) {
	log := logger.New(nil, false)
	disp := NewDispatcher(log)

	handler := &mockHandler{name: "test-handler"}
	_ = disp.Register(handler)

	err := disp.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Try to dispatch after close
	event := &mockEvent{valid: true}
	err = disp.Dispatch(event)
	if err == nil {
		t.Error("Dispatch() should return error when dispatcher is closed")
	}
}
