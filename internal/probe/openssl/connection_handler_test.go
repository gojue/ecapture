// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package openssl

import (
	"testing"

	"github.com/gojue/ecapture/v2/internal/domain"
)

func TestConnectionHandlerUpdatesInternalState(t *testing.T) {
	handler := newConnectionHandler()
	event := &ConnDataEvent{
		connDataEvent: connDataEvent{
			Pid:  123,
			Fd:   7,
			Sock: 99,
		},
		Tuple: "[127.0.0.1]:12345->[127.0.0.1]:443",
	}

	if !handler.Supports(event) {
		t.Fatal("connection handler should support connection module data")
	}
	if handler.Writer() != nil {
		t.Fatal("internal connection handler must not expose an output writer")
	}
	if err := handler.Handle(event); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	info, ok := handler.lookup(event.Pid, event.Fd)
	if !ok {
		t.Fatal("connection was not stored")
	}
	if info.tuple != event.Tuple || info.sock != event.Sock {
		t.Fatalf("stored connection = %#v, want tuple %q sock %d", info, event.Tuple, event.Sock)
	}

	destroy := event.Clone().(*ConnDataEvent)
	destroy.IsDestroy = 1
	if err := handler.Handle(destroy); err != nil {
		t.Fatalf("Handle(destroy) error = %v", err)
	}
	if _, ok := handler.lookup(event.Pid, event.Fd); ok {
		t.Fatal("destroyed connection remains in state")
	}
}

func TestConnectionHandlerRejectsOtherModuleData(t *testing.T) {
	handler := newConnectionHandler()
	event := &MasterSecretEvent{}
	if event.Type() != domain.EventTypeModuleData {
		t.Fatalf("master secret type = %v, want module data", event.Type())
	}
	if handler.Supports(event) {
		t.Fatal("connection handler must not support secret module data")
	}
}
