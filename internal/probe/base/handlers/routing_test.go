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

package handlers

import (
	"bytes"
	"testing"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/events"
	"github.com/gojue/ecapture/v2/internal/logger"
)

type mockGoTLSSecretEvent struct {
	clientRandom []byte
	secret       []byte
}

func (m *mockGoTLSSecretEvent) GetLabel() string             { return "CLIENT_RANDOM" }
func (m *mockGoTLSSecretEvent) GetClientRandom() []byte      { return m.clientRandom }
func (m *mockGoTLSSecretEvent) GetSecret() []byte            { return m.secret }
func (m *mockGoTLSSecretEvent) DecodeFromBytes([]byte) error { return nil }
func (m *mockGoTLSSecretEvent) String() string               { return "go secret" }
func (m *mockGoTLSSecretEvent) StringHex() string            { return "go secret hex" }
func (m *mockGoTLSSecretEvent) Clone() domain.Event          { return &mockGoTLSSecretEvent{} }
func (m *mockGoTLSSecretEvent) Type() domain.EventType       { return domain.EventTypeModuleData }
func (m *mockGoTLSSecretEvent) UUID() string                 { return "go-secret" }
func (m *mockGoTLSSecretEvent) Validate() error              { return nil }

type mockTypedEvent struct {
	eventType domain.EventType
}

func (m *mockTypedEvent) DecodeFromBytes([]byte) error { return nil }
func (m *mockTypedEvent) String() string               { return "typed" }
func (m *mockTypedEvent) StringHex() string            { return "7479706564" }
func (m *mockTypedEvent) Clone() domain.Event {
	return &mockTypedEvent{eventType: m.eventType}
}
func (m *mockTypedEvent) Type() domain.EventType { return m.eventType }
func (m *mockTypedEvent) UUID() string           { return "typed" }
func (m *mockTypedEvent) Validate() error        { return nil }

func TestHandlerRoutingMatrix(t *testing.T) {
	secretEvents := []struct {
		library string
		event   domain.Event
	}{
		{library: "openssl", event: &mockMasterSecretEvent{}},
		{library: "gotls", event: &mockGoTLSSecretEvent{}},
		{library: "gnutls", event: &mockDirectTrafficSecretEvent{}},
	}

	for _, useHex := range []bool{false, true} {
		for _, secret := range secretEvents {
			t.Run(secret.library+"/hex="+boolName(useHex), func(t *testing.T) {
				text := NewTextHandler(newMockWriter(), useHex)
				keylog := NewKeylogHandler(newMockKeylogWriter())
				pcap := &PcapHandler{writer: newMockPcapWriter()}

				data := &mockTLSDataEvent{}
				packet := &mockPacketEvent{}
				control := &mockTypedEvent{eventType: domain.EventTypeModuleData}
				processor := &mockTypedEvent{eventType: domain.EventTypeProcessor}

				assertSupports(t, "text/data", text, data, true)
				assertSupports(t, "text/secret", text, secret.event, false)
				assertSupports(t, "text/packet", text, packet, false)
				assertSupports(t, "text/control", text, control, false)
				assertSupports(t, "text/processor", text, processor, false)

				assertSupports(t, "keylog/data", keylog, data, false)
				assertSupports(t, "keylog/secret", keylog, secret.event, true)
				assertSupports(t, "keylog/packet", keylog, packet, false)
				assertSupports(t, "keylog/control", keylog, control, false)
				assertSupports(t, "keylog/processor", keylog, processor, false)

				assertSupports(t, "pcap/data", pcap, data, false)
				assertSupports(t, "pcap/secret", pcap, secret.event, false)
				assertSupports(t, "pcap/packet", pcap, packet, true)
				assertSupports(t, "pcap/control", pcap, control, false)
				assertSupports(t, "pcap/processor", pcap, processor, false)
			})
		}
	}
}

func TestSecretNeverReachesTextWriter(t *testing.T) {
	filled := func(length int, value byte) []byte {
		return bytes.Repeat([]byte{value}, length)
	}
	secretEvents := []struct {
		library string
		event   domain.Event
	}{
		{
			library: "openssl",
			event: &mockMasterSecretEvent{
				version:      0x0303,
				clientRandom: filled(Ssl3RandomSize, 0x11),
				masterKey:    filled(MasterSecretMaxLen, 0x22),
			},
		},
		{
			library: "gotls",
			event: &mockGoTLSSecretEvent{
				clientRandom: filled(Ssl3RandomSize, 0x33),
				secret:       filled(MasterSecretMaxLen, 0x44),
			},
		},
		{
			library: "gnutls",
			event: &mockDirectTrafficSecretEvent{
				clientRandom: filled(Ssl3RandomSize, 0x55),
				masterKey:    filled(MasterSecretMaxLen, 0x66),
			},
		},
	}

	for _, useHex := range []bool{false, true} {
		for _, secret := range secretEvents {
			t.Run(secret.library+"/hex="+boolName(useHex), func(t *testing.T) {
				textWriter := newMockWriter()
				keylogWriter := newMockKeylogWriter()
				dispatcher := events.NewDispatcher(logger.New(nil, false))
				if err := dispatcher.Register(NewTextHandler(textWriter, useHex)); err != nil {
					t.Fatalf("register text handler: %v", err)
				}
				if err := dispatcher.Register(NewKeylogHandler(keylogWriter)); err != nil {
					t.Fatalf("register keylog handler: %v", err)
				}

				if err := dispatcher.Dispatch(secret.event); err != nil {
					t.Fatalf("Dispatch() error = %v", err)
				}
				if textWriter.Len() != 0 {
					t.Fatalf("secret leaked to text writer: %q", textWriter.String())
				}
				if keylogWriter.Len() == 0 {
					t.Fatal("secret did not reach keylog writer")
				}
			})
		}
	}
}

func assertSupports(t *testing.T, name string, handler domain.EventHandler, event domain.Event, want bool) {
	t.Helper()
	if got := handler.Supports(event); got != want {
		t.Errorf("%s Supports() = %t, want %t", name, got, want)
	}
}

func boolName(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
