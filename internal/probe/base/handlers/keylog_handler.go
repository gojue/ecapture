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
	"sync"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/output/writers"
)

const (
	// SSL/TLS key sizes
	Ssl3RandomSize     = 32
	MasterSecretMaxLen = 48
	EvpMaxMdSize       = 64
)

const (
	KeyLogLabelTLS12                   = "CLIENT_RANDOM"
	KeyLogLabelClientEarlyTafficSecret = "CLIENT_EARLY_TRAFFIC_SECRET"

	KeyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	KeyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
	KeyLogLabelExporterSecret  = "EXPORTER_SECRET"
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
	GetEarlySecret() []byte
	GetHandshakeSecret() []byte
	GetHandshakeTrafficHash() []byte
	GetClientAppTrafficSecret() []byte
	GetServerAppTrafficSecret() []byte
	GetExporterMasterSecret() []byte
}

// GoTLSMasterSecretEvent defines the interface for GoTLS-style master secret events.
// GoTLS uses a label-based format (e.g., "CLIENT_HANDSHAKE_TRAFFIC_SECRET").
type GoTLSMasterSecretEvent interface {
	domain.Event
	GetLabel() string
	GetClientRandom() []byte
	GetSecret() []byte
}

// KeylogHandler handles TLS master secret events by writing them in NSS Key Log Format.
// The output format is compatible with Wireshark for TLS decryption.
//
// NSS Key Log Format:
//
//	CLIENT_RANDOM <64 hex digits client random> <96 hex digits master secret>
//	CLIENT_HANDSHAKE_TRAFFIC_SECRET <64 hex digits> <64+ hex digits>
//	SERVER_HANDSHAKE_TRAFFIC_SECRET <64 hex digits> <64+ hex digits>
//	CLIENT_TRAFFIC_SECRET_0 <64 hex digits> <64+ hex digits>
//	SERVER_TRAFFIC_SECRET_0 <64 hex digits> <64+ hex digits>
//	EXPORTER_SECRET <64 hex digits> <64+ hex digits>
type KeylogHandler struct {
	writer   writers.OutputWriter
	mu       sync.Mutex
	seenKeys map[string]bool // Deduplicate keys
}

func (h *KeylogHandler) Writer() writers.OutputWriter {
	return h.writer
}

// NewKeylogHandler creates a new KeylogHandler with the provided writer.
func NewKeylogHandler(writer writers.OutputWriter) *KeylogHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
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

	h.mu.Lock()
	defer h.mu.Unlock()

	// Try GoTLS-style event first (label-based format)
	if goEvent, ok := event.(GoTLSMasterSecretEvent); ok {
		return h.handleGoTLS(goEvent)
	}

	// Try OpenSSL-style event (version-based format)
	msEvent, ok := event.(MasterSecretEvent)
	if !ok {
		return errors.New(errors.ErrCodeEventValidation, "event is not a master secret event")
	}

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

	// Skip if master key is all zeros (eBPF captured before handshake completion)
	if isZeroBytes(masterKey[:MasterSecretMaxLen]) {
		return nil // Silently skip - not an error, just captured too early
	}

	// Format: CLIENT_RANDOM <client_random> <master_secret>
	line := fmt.Sprintf("%s %x %x\n",
		KeyLogLabelTLS12,
		clientRandom[:Ssl3RandomSize],
		masterKey[:MasterSecretMaxLen])

	// Use client_random as dedup key to avoid multiple captures of same connection
	// This ensures we only write the first valid (non-zero) master secret
	dedupKey := fmt.Sprintf("%s_%x", KeyLogLabelTLS12, clientRandom[:Ssl3RandomSize])
	if h.seenKeys[dedupKey] {
		return nil // Skip duplicate - already captured this connection
	}

	// Write to output
	if _, err := h.writer.Write([]byte(line)); err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write keylog entry", err)
	}
	err := h.writer.Flush()
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to flush keylog entry", err)
	}
	// Mark this client_random as seen
	h.seenKeys[dedupKey] = true
	return nil
}

// handleGoTLS writes GoTLS-style master secrets using label-based format.
// Format: LABEL CLIENT_RANDOM SECRET
func (h *KeylogHandler) handleGoTLS(event GoTLSMasterSecretEvent) error {
	label := event.GetLabel()
	clientRandom := event.GetClientRandom()
	secret := event.GetSecret()

	if label == "" {
		return errors.New(errors.ErrCodeEventValidation, "label is empty")
	}
	if len(clientRandom) == 0 {
		return errors.New(errors.ErrCodeEventValidation, "client random is empty")
	}
	if len(secret) == 0 {
		return errors.New(errors.ErrCodeEventValidation, "secret is empty")
	}

	// Skip if secret is all zeros (eBPF captured before handshake completion)
	if isZeroBytes(secret) {
		return nil // Silently skip - not an error, just captured too early
	}

	// Format: LABEL <client_random_hex> <secret_hex>
	// This is the standard NSS Key Log Format used by Wireshark
	line := fmt.Sprintf("%s %x %x\n", label, clientRandom, secret)

	// Use label+client_random as dedup key to avoid multiple captures
	dedupKey := fmt.Sprintf("%s_%x", label, clientRandom)
	if h.seenKeys[dedupKey] {
		return nil // Skip duplicate - already captured
	}

	// Write to output
	if _, err := h.writer.Write([]byte(line)); err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write keylog entry", err)
	}

	// Mark as seen
	h.seenKeys[dedupKey] = true
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

		{KeyLogLabelClientTraffic, event.GetClientAppTrafficSecret()},
		{KeyLogLabelServerTraffic, event.GetServerAppTrafficSecret()},
		{KeyLogLabelExporterSecret, event.GetExporterMasterSecret()},
		{KeyLogLabelServerHandshake, event.GetHandshakeSecret()},
		//{KeyLogLabelClientEarlyTafficSecret, event.GetEarlySecret()},
	}

	for _, secret := range secrets {
		if len(secret.data) == 0 || isZeroBytes(secret.data) {
			continue // Skip empty or zero secrets
		}

		// Use label+client_random as dedup key
		dedupKey := fmt.Sprintf("%s_%s", secret.label, clientRandomHex)
		if h.seenKeys[dedupKey] {
			continue // Already written this secret type for this connection
		}

		line := fmt.Sprintf("%s %s %x\n", secret.label, clientRandomHex, secret.data)

		// Write to output
		if _, err := h.writer.Write([]byte(line)); err != nil {
			return errors.Wrap(errors.ErrCodeEventDispatch,
				fmt.Sprintf("failed to write %s", secret.label), err)
		}

		h.seenKeys[dedupKey] = true
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *KeylogHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Clear the seen keys map
	h.seenKeys = make(map[string]bool)

	err := h.writer.Flush()

	if err != nil {
		return err
	}

	// Close the writer
	if h.writer != nil {
		return h.writer.Close()
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

// Name returns the handler's identifier.
func (h *KeylogHandler) Name() string {
	return ModeKeylog
}
