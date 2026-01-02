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
	"sync"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	// SSL/TLS key sizes
	Ssl3RandomSize     = 32
	MasterSecretMaxLen = 48
	EvpMaxMdSize       = 64
)

// MasterSecretEvent defines the interface for master secret key events.
// This follows the NSS Key Log Format used by Wireshark and other tools.
type MasterSecretEvent interface {
	domain.Event
	GetVersion() int32
	GetClientRandom() []byte
	GetMasterKey() []byte
	// TLS 1.3 specific methods
	GetCipherId() uint32
	GetClientHandshakeTrafficSecret() []byte
	GetServerHandshakeTrafficSecret() []byte
	GetClientAppTrafficSecret() []byte
	GetServerAppTrafficSecret() []byte
	GetExporterMasterSecret() []byte
}

// KeylogHandler handles TLS master secret events by writing them in NSS Key Log Format.
// The output format is compatible with Wireshark for TLS decryption.
//
// NSS Key Log Format:
//   CLIENT_RANDOM <64 hex digits client random> <96 hex digits master secret>
//   CLIENT_HANDSHAKE_TRAFFIC_SECRET <64 hex digits> <64+ hex digits>
//   SERVER_HANDSHAKE_TRAFFIC_SECRET <64 hex digits> <64+ hex digits>
//   CLIENT_TRAFFIC_SECRET_0 <64 hex digits> <64+ hex digits>
//   SERVER_TRAFFIC_SECRET_0 <64 hex digits> <64+ hex digits>
//   EXPORTER_SECRET <64 hex digits> <64+ hex digits>
type KeylogHandler struct {
	writer     io.Writer
	mu         sync.Mutex
	seenKeys   map[string]bool // Deduplicate keys
}

// NewKeylogHandler creates a new KeylogHandler that writes to the provided writer.
func NewKeylogHandler(writer io.Writer) *KeylogHandler {
	if writer == nil {
		writer = io.Discard
	}
	return &KeylogHandler{
		writer:   writer,
		seenKeys: make(map[string]bool),
	}
}

// Handle processes a master secret event and writes it in NSS Key Log Format.
func (h *KeylogHandler) Handle(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventValidation, "event cannot be nil")
	}

	// Type assert to master secret event
	msEvent, ok := event.(MasterSecretEvent)
	if !ok {
		return errors.New(errors.ErrCodeEventValidation, "event is not a master secret event")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	version := msEvent.GetVersion()

	// TLS 1.2 and earlier use CLIENT_RANDOM format
	if version <= 0x0303 { // TLS 1.2 = 0x0303
		return h.handleTLS12(msEvent)
	}

	// TLS 1.3 uses multiple secret types
	return h.handleTLS13(msEvent)
}

// handleTLS12 writes TLS 1.2 (and earlier) master secrets.
func (h *KeylogHandler) handleTLS12(event MasterSecretEvent) error {
	clientRandom := event.GetClientRandom()
	masterKey := event.GetMasterKey()

	if len(clientRandom) < Ssl3RandomSize {
		return errors.New(errors.ErrCodeEventValidation, 
			fmt.Sprintf("client random too short: %d bytes", len(clientRandom)))
	}
	if len(masterKey) < MasterSecretMaxLen {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("master key too short: %d bytes", len(masterKey)))
	}

	// Format: CLIENT_RANDOM <client_random> <master_secret>
	line := fmt.Sprintf("CLIENT_RANDOM %x %x\n",
		clientRandom[:Ssl3RandomSize],
		masterKey[:MasterSecretMaxLen])

	// Check if we've already written this key
	if h.seenKeys[line] {
		return nil // Skip duplicate
	}

	// Write to output
	if _, err := h.writer.Write([]byte(line)); err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write keylog entry", err)
	}

	h.seenKeys[line] = true
	return nil
}

// handleTLS13 writes TLS 1.3 secrets.
func (h *KeylogHandler) handleTLS13(event MasterSecretEvent) error {
	clientRandom := event.GetClientRandom()
	if len(clientRandom) < Ssl3RandomSize {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("client random too short: %d bytes", len(clientRandom)))
	}

	clientRandomHex := fmt.Sprintf("%x", clientRandom[:Ssl3RandomSize])

	// Write each TLS 1.3 secret type if available
	secrets := []struct {
		label string
		data  []byte
	}{
		{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", event.GetClientHandshakeTrafficSecret()},
		{"SERVER_HANDSHAKE_TRAFFIC_SECRET", event.GetServerHandshakeTrafficSecret()},
		{"CLIENT_TRAFFIC_SECRET_0", event.GetClientAppTrafficSecret()},
		{"SERVER_TRAFFIC_SECRET_0", event.GetServerAppTrafficSecret()},
		{"EXPORTER_SECRET", event.GetExporterMasterSecret()},
	}

	for _, secret := range secrets {
		if len(secret.data) == 0 || isZeroBytes(secret.data) {
			continue // Skip empty or zero secrets
		}

		line := fmt.Sprintf("%s %s %x\n", secret.label, clientRandomHex, secret.data)

		// Check for duplicate
		if h.seenKeys[line] {
			continue
		}

		// Write to output
		if _, err := h.writer.Write([]byte(line)); err != nil {
			return errors.Wrap(errors.ErrCodeEventDispatch, 
				fmt.Sprintf("failed to write %s", secret.label), err)
		}

		h.seenKeys[line] = true
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *KeylogHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Clear the seen keys map
	h.seenKeys = make(map[string]bool)

	// Check if writer implements io.Closer
	if closer, ok := h.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// isZeroBytes checks if a byte slice contains only zeros.
func isZeroBytes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
