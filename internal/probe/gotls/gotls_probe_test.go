// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package gotls

import (
	"testing"

	"github.com/gojue/ecapture/internal/domain"
)

// mockDispatcher implements domain.EventDispatcher for testing
type mockDispatcher struct{}

func (m *mockDispatcher) Register(handler domain.EventHandler) error { return nil }
func (m *mockDispatcher) Unregister(handlerName string) error        { return nil }
func (m *mockDispatcher) Dispatch(event domain.Event) error          { return nil }
func (m *mockDispatcher) Close() error                               { return nil }

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	if probe == nil {
		t.Fatal("NewProbe() returned nil")
	}
}

func TestProbe_Initialize_TextMode(t *testing.T) {
	t.Skip("requires ElfPath to be set for GoTLS probe initialization")
}

func TestProbe_Initialize_KeylogMode(t *testing.T) {
	t.Skip("requires ElfPath to be set for GoTLS probe initialization")
}

func TestProbe_Initialize_PcapMode(t *testing.T) {
	t.Skip("requires ElfPath to be set for GoTLS probe initialization")
}

func TestProbe_Close(t *testing.T) {
	t.Skip("requires ElfPath to be set for GoTLS probe initialization")
}
