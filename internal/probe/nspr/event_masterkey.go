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

package nspr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	// ClientRandomSize is the size of client random (32 bytes)
	ClientRandomSize = 32

	// MasterKeySize is the size of master key for TLS 1.2 (48 bytes)
	MasterKeySize = 48

	// TrafficSecretSize is the size of traffic secret for TLS 1.3 (64 bytes max)
	TrafficSecretSize = 64
)

// MasterSecretEvent represents a TLS master secret event from NSPR/NSS
type MasterSecretEvent struct {
	// ClientRandom is the client random value (32 bytes)
	ClientRandom [ClientRandomSize]byte

	// MasterKey is the master key for TLS 1.2 (48 bytes)
	MasterKey [MasterKeySize]byte

	// ClientHandshakeTrafficSecret for TLS 1.3
	ClientHandshakeTrafficSecret [TrafficSecretSize]byte

	// ServerHandshakeTrafficSecret for TLS 1.3
	ServerHandshakeTrafficSecret [TrafficSecretSize]byte

	// ClientAppTrafficSecret for TLS 1.3
	ClientAppTrafficSecret [TrafficSecretSize]byte

	// ServerAppTrafficSecret for TLS 1.3
	ServerAppTrafficSecret [TrafficSecretSize]byte

	// ExporterMasterSecret for TLS 1.3
	ExporterMasterSecret [TrafficSecretSize]byte
}

// GetClientRandom returns the client random as a byte slice
func (e *MasterSecretEvent) GetClientRandom() []byte {
	return e.ClientRandom[:]
}

// GetMasterKey returns the master key (TLS 1.2)
func (e *MasterSecretEvent) GetMasterKey() []byte {
	return e.MasterKey[:]
}

// GetClientHandshakeTrafficSecret returns the client handshake traffic secret (TLS 1.3)
func (e *MasterSecretEvent) GetClientHandshakeTrafficSecret() []byte {
	return e.ClientHandshakeTrafficSecret[:]
}

// GetServerHandshakeTrafficSecret returns the server handshake traffic secret (TLS 1.3)
func (e *MasterSecretEvent) GetServerHandshakeTrafficSecret() []byte {
	return e.ServerHandshakeTrafficSecret[:]
}

// GetClientAppTrafficSecret returns the client application traffic secret (TLS 1.3)
func (e *MasterSecretEvent) GetClientAppTrafficSecret() []byte {
	return e.ClientAppTrafficSecret[:]
}

// GetServerAppTrafficSecret returns the server application traffic secret (TLS 1.3)
func (e *MasterSecretEvent) GetServerAppTrafficSecret() []byte {
	return e.ServerAppTrafficSecret[:]
}

// GetExporterMasterSecret returns the exporter master secret (TLS 1.3)
func (e *MasterSecretEvent) GetExporterMasterSecret() []byte {
	return e.ExporterMasterSecret[:]
}

// HasMasterKey returns true if master key is present (TLS 1.2)
func (e *MasterSecretEvent) HasMasterKey() bool {
	// Check if master key is non-zero
	for _, b := range e.MasterKey {
		if b != 0 {
			return true
		}
	}
	return false
}

// HasClientHandshakeTrafficSecret returns true if client handshake traffic secret is present (TLS 1.3)
func (e *MasterSecretEvent) HasClientHandshakeTrafficSecret() bool {
	for _, b := range e.ClientHandshakeTrafficSecret {
		if b != 0 {
			return true
		}
	}
	return false
}

// DecodeFromBytes implements domain.Event interface
func (e *MasterSecretEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewReader(data)

	// Read ClientRandom
	if err := binary.Read(buf, binary.LittleEndian, &e.ClientRandom); err != nil {
		return errors.NewEventDecodeError("nspr.ClientRandom", err)
	}

	// Read MasterKey
	if err := binary.Read(buf, binary.LittleEndian, &e.MasterKey); err != nil {
		return errors.NewEventDecodeError("nspr.MasterKey", err)
	}

	// Read ClientHandshakeTrafficSecret
	if err := binary.Read(buf, binary.LittleEndian, &e.ClientHandshakeTrafficSecret); err != nil {
		return errors.NewEventDecodeError("nspr.ClientHandshakeTrafficSecret", err)
	}

	// Read ServerHandshakeTrafficSecret
	if err := binary.Read(buf, binary.LittleEndian, &e.ServerHandshakeTrafficSecret); err != nil {
		return errors.NewEventDecodeError("nspr.ServerHandshakeTrafficSecret", err)
	}

	// Read ClientAppTrafficSecret
	if err := binary.Read(buf, binary.LittleEndian, &e.ClientAppTrafficSecret); err != nil {
		return errors.NewEventDecodeError("nspr.ClientAppTrafficSecret", err)
	}

	// Read ServerAppTrafficSecret
	if err := binary.Read(buf, binary.LittleEndian, &e.ServerAppTrafficSecret); err != nil {
		return errors.NewEventDecodeError("nspr.ServerAppTrafficSecret", err)
	}

	// Read ExporterMasterSecret
	if err := binary.Read(buf, binary.LittleEndian, &e.ExporterMasterSecret); err != nil {
		return errors.NewEventDecodeError("nspr.ExporterMasterSecret", err)
	}

	return nil
}

// String implements domain.Event interface
func (e *MasterSecretEvent) String() string {
	clientRandom := hex.EncodeToString(e.ClientRandom[:])

	result := fmt.Sprintf("MasterSecretEvent{ClientRandom: %s", clientRandom)

	if e.HasMasterKey() {
		result += ", MasterKey: <present>"
	}

	if e.HasClientHandshakeTrafficSecret() {
		result += ", TLS1.3 secrets: <present>"
	}

	result += "}"
	return result
}

// StringHex implements domain.Event interface
func (e *MasterSecretEvent) StringHex() string {
	// Same as String for master secret events
	return e.String()
}

// Clone implements domain.Event interface
func (e *MasterSecretEvent) Clone() domain.Event {
	return &MasterSecretEvent{}
}

// Type implements domain.Event interface
func (e *MasterSecretEvent) Type() domain.EventType {
	return domain.EventTypeModuleData
}

// UUID implements domain.Event interface
func (e *MasterSecretEvent) UUID() string {
	return hex.EncodeToString(e.ClientRandom[:])
}

// Validate implements domain.Event interface
func (e *MasterSecretEvent) Validate() error {
	// Check if at least one secret is present
	if !e.HasMasterKey() && !e.HasClientHandshakeTrafficSecret() {
		return fmt.Errorf("no secrets present in master secret event")
	}
	return nil
}

// Decode is kept for backward compatibility
func (e *MasterSecretEvent) Decode(data []byte) error {
	return e.DecodeFromBytes(data)
}

// Encode encodes a MasterSecretEvent to binary data
func (e *MasterSecretEvent) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write ClientRandom
	if err := binary.Write(buf, binary.LittleEndian, e.ClientRandom); err != nil {
		return nil, fmt.Errorf("failed to write client random: %w", err)
	}

	// Write MasterKey
	if err := binary.Write(buf, binary.LittleEndian, e.MasterKey); err != nil {
		return nil, fmt.Errorf("failed to write master key: %w", err)
	}

	// Write ClientHandshakeTrafficSecret
	if err := binary.Write(buf, binary.LittleEndian, e.ClientHandshakeTrafficSecret); err != nil {
		return nil, fmt.Errorf("failed to write client handshake traffic secret: %w", err)
	}

	// Write ServerHandshakeTrafficSecret
	if err := binary.Write(buf, binary.LittleEndian, e.ServerHandshakeTrafficSecret); err != nil {
		return nil, fmt.Errorf("failed to write server handshake traffic secret: %w", err)
	}

	// Write ClientAppTrafficSecret
	if err := binary.Write(buf, binary.LittleEndian, e.ClientAppTrafficSecret); err != nil {
		return nil, fmt.Errorf("failed to write client app traffic secret: %w", err)
	}

	// Write ServerAppTrafficSecret
	if err := binary.Write(buf, binary.LittleEndian, e.ServerAppTrafficSecret); err != nil {
		return nil, fmt.Errorf("failed to write server app traffic secret: %w", err)
	}

	// Write ExporterMasterSecret
	if err := binary.Write(buf, binary.LittleEndian, e.ExporterMasterSecret); err != nil {
		return nil, fmt.Errorf("failed to write exporter master secret: %w", err)
	}

	return buf.Bytes(), nil
}
