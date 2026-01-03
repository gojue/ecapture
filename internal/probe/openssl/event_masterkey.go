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

package openssl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

const (
	// SSL/TLS constants
	Ssl3RandomSize     = handlers.Ssl3RandomSize     // 32 bytes
	MasterSecretMaxLen = handlers.MasterSecretMaxLen // 48 bytes
	EvpMaxMdSize       = handlers.EvpMaxMdSize       // 64 bytes
)

// MasterSecretEvent represents a TLS master secret key event from eBPF.
// This event contains the master secret and related cryptographic material
// needed to decrypt TLS traffic.
//
// The structure must match the kernel's mastersecret_t exactly.
//
// For TLS 1.2 and earlier:
//   - ClientRandom: 32-byte client random value
//   - MasterKey: 48-byte master secret
//
// For TLS 1.3:
//   - ClientRandom: 32-byte client random value
//   - Multiple traffic secrets (handshake, application, exporter)
type MasterSecretEvent struct {
	// TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
	Version int32 `json:"version"`

	// TLS 1.2 and earlier
	ClientRandom [Ssl3RandomSize]byte     `json:"clientRandom"` // Client random value
	MasterKey    [MasterSecretMaxLen]byte `json:"masterKey"`    // Master secret

	// TLS 1.3 secrets
	CipherId               uint32             `json:"cipherId"`               // Cipher suite ID
	EarlySecret            [EvpMaxMdSize]byte `json:"earlySecret"`            // EARLY_EXPORTER_SECRET
	HandshakeSecret        [EvpMaxMdSize]byte `json:"handshakeSecret"`        // Handshake secret (internal)
	HandshakeTrafficHash   [EvpMaxMdSize]byte `json:"handshakeTrafficHash"`   // Handshake traffic hash
	ClientAppTrafficSecret [EvpMaxMdSize]byte `json:"clientAppTrafficSecret"` // CLIENT_TRAFFIC_SECRET_0
	ServerAppTrafficSecret [EvpMaxMdSize]byte `json:"serverAppTrafficSecret"` // SERVER_TRAFFIC_SECRET_0
	ExporterMasterSecret   [EvpMaxMdSize]byte `json:"exporterMasterSecret"`   // EXPORTER_SECRET
}

// DecodeFromBytes deserializes the master secret event from raw eBPF data.
func (e *MasterSecretEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read TLS version
	if err := binary.Read(buf, binary.LittleEndian, &e.Version); err != nil {
		return errors.NewEventDecodeError("masterSecret.Version", err)
	}

	// Read client random
	if err := binary.Read(buf, binary.LittleEndian, &e.ClientRandom); err != nil {
		return errors.NewEventDecodeError("masterSecret.ClientRandom", err)
	}

	// Read master key (TLS 1.2)
	if err := binary.Read(buf, binary.LittleEndian, &e.MasterKey); err != nil {
		return errors.NewEventDecodeError("masterSecret.MasterKey", err)
	}

	// For TLS 1.3, read additional secrets if available
	if buf.Len() >= 4 {
		if err := binary.Read(buf, binary.LittleEndian, &e.CipherId); err != nil {
			// CipherId might not be present
			e.CipherId = 0
		}
	}

	if buf.Len() >= EvpMaxMdSize {
		if err := binary.Read(buf, binary.LittleEndian, &e.EarlySecret); err != nil {
			// Not all TLS 1.3 secrets might be present
		}
	}

	if buf.Len() >= EvpMaxMdSize {
		if err := binary.Read(buf, binary.LittleEndian, &e.HandshakeSecret); err != nil {
			// Not all TLS 1.3 secrets might be present
		}
	}

	if buf.Len() >= EvpMaxMdSize {
		if err := binary.Read(buf, binary.LittleEndian, &e.HandshakeTrafficHash); err != nil {
			// Not all TLS 1.3 secrets might be present
		}
	}

	if buf.Len() >= EvpMaxMdSize {
		if err := binary.Read(buf, binary.LittleEndian, &e.ClientAppTrafficSecret); err != nil {
			// Not all TLS 1.3 secrets might be present
		}
	}

	if buf.Len() >= EvpMaxMdSize {
		if err := binary.Read(buf, binary.LittleEndian, &e.ServerAppTrafficSecret); err != nil {
			// Not all TLS 1.3 secrets might be present
		}
	}

	if buf.Len() >= EvpMaxMdSize {
		if err := binary.Read(buf, binary.LittleEndian, &e.ExporterMasterSecret); err != nil {
			// Not all TLS 1.3 secrets might be present
		}
	}

	return nil
}

// String returns a human-readable representation of the master secret event.
func (e *MasterSecretEvent) String() string {
	versionStr := fmt.Sprintf("0x%04x", e.Version)
	if e.Version == 0x0303 {
		versionStr = "TLS 1.2"
	} else if e.Version == 0x0304 {
		versionStr = "TLS 1.3"
	}

	return fmt.Sprintf("TLS Version: %s, ClientRandom: %x",
		versionStr,
		e.ClientRandom[:]) // Show full 32 bytes of client random
}

// StringHex returns a hexadecimal representation of the event.
func (e *MasterSecretEvent) StringHex() string {
	return fmt.Sprintf("Version: 0x%04x, ClientRandom: %x, MasterKey: %x",
		e.Version,
		e.ClientRandom,
		e.MasterKey)
}

// Clone creates a new instance of the event.
func (e *MasterSecretEvent) Clone() domain.Event {
	clone := *e
	return &clone
}

// Type returns the event type.
func (e *MasterSecretEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for this event.
func (e *MasterSecretEvent) UUID() string {
	// Use hash of full ClientRandom for better uniqueness
	h := fnv.New64a()
	h.Write(e.ClientRandom[:])
	return fmt.Sprintf("ms_%x", h.Sum64())
}

// Validate checks if the event data is valid.
func (e *MasterSecretEvent) Validate() error {
	// Check version is valid (TLS 1.0 to 1.3)
	if e.Version < 0x0301 || e.Version > 0x0304 {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid TLS version: 0x%04x", e.Version))
	}

	// Check that at least client random is not all zeros
	allZero := true
	for _, b := range e.ClientRandom {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return errors.New(errors.ErrCodeEventValidation, "client random is all zeros")
	}

	return nil
}

// Implementation of handlers.MasterSecretEvent interface

// GetVersion returns the TLS version.
func (e *MasterSecretEvent) GetVersion() int32 {
	return e.Version
}

// GetClientRandom returns the client random value.
func (e *MasterSecretEvent) GetClientRandom() []byte {
	return e.ClientRandom[:]
}

// GetMasterKey returns the master secret (TLS 1.2 and earlier).
func (e *MasterSecretEvent) GetMasterKey() []byte {
	return e.MasterKey[:]
}

// GetCipherId returns the cipher suite ID (TLS 1.3).
func (e *MasterSecretEvent) GetCipherId() uint32 {
	return e.CipherId
}

// GetEarlySecret returns the early secret (TLS 1.3).
func (e *MasterSecretEvent) GetEarlySecret() []byte {
	return e.EarlySecret[:]
}

// GetHandshakeSecret returns the handshake secret (TLS 1.3, internal).
func (e *MasterSecretEvent) GetHandshakeSecret() []byte {
	return e.HandshakeSecret[:]
}

// GetHandshakeTrafficHash returns the handshake traffic hash (TLS 1.3).
func (e *MasterSecretEvent) GetHandshakeTrafficHash() []byte {
	return e.HandshakeTrafficHash[:]
}

// GetClientAppTrafficSecret returns the client application traffic secret (TLS 1.3).
func (e *MasterSecretEvent) GetClientAppTrafficSecret() []byte {
	return e.ClientAppTrafficSecret[:]
}

// GetServerAppTrafficSecret returns the server application traffic secret (TLS 1.3).
func (e *MasterSecretEvent) GetServerAppTrafficSecret() []byte {
	return e.ServerAppTrafficSecret[:]
}

// GetExporterMasterSecret returns the exporter master secret (TLS 1.3).
func (e *MasterSecretEvent) GetExporterMasterSecret() []byte {
	return e.ExporterMasterSecret[:]
}
