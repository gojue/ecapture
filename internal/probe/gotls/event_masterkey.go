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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// MasterSecretEvent represents a TLS master secret event from GoTLS
// This structure matches the eBPF event structure for TLS key material
type MasterSecretEvent struct {
	Timestamp                    uint64   // Timestamp in nanoseconds
	Pid                          uint32   // Process ID
	Tid                          uint32   // Thread ID
	ClientRandom                 [32]byte // Client random (32 bytes)
	MasterKey                    [48]byte // Master key for TLS 1.2 (48 bytes)
	ClientHandshakeTrafficSecret [64]byte // Client handshake traffic secret for TLS 1.3
	ServerHandshakeTrafficSecret [64]byte // Server handshake traffic secret for TLS 1.3
	ClientAppTrafficSecret       [64]byte // Client application traffic secret for TLS 1.3
	ServerAppTrafficSecret       [64]byte // Server application traffic secret for TLS 1.3
	ExporterMasterSecret         [64]byte // Exporter master secret for TLS 1.3
}

// DecodeFromBytes deserializes the event from raw eBPF data.
func (e *MasterSecretEvent) DecodeFromBytes(data []byte) error {
	expectedSize := 8 + 4 + 4 + 32 + 48 + 64*5 // 406 bytes
	if len(data) < expectedSize {
		return errors.NewEventDecodeError("gotls.MasterSecretEvent", 
			fmt.Errorf("data too short: got %d bytes, need at least %d", len(data), expectedSize))
	}

	buf := bytes.NewBuffer(data)

	// Read timestamp
	if err := binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return errors.NewEventDecodeError("gotls.Timestamp", err)
	}

	// Read PID
	if err := binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return errors.NewEventDecodeError("gotls.Pid", err)
	}

	// Read TID
	if err := binary.Read(buf, binary.LittleEndian, &e.Tid); err != nil {
		return errors.NewEventDecodeError("gotls.Tid", err)
	}

	// Read client random
	if _, err := buf.Read(e.ClientRandom[:]); err != nil {
		return errors.NewEventDecodeError("gotls.ClientRandom", err)
	}

	// Read master key (TLS 1.2)
	if _, err := buf.Read(e.MasterKey[:]); err != nil {
		return errors.NewEventDecodeError("gotls.MasterKey", err)
	}

	// Read TLS 1.3 secrets
	if _, err := buf.Read(e.ClientHandshakeTrafficSecret[:]); err != nil {
		return errors.NewEventDecodeError("gotls.ClientHandshakeTrafficSecret", err)
	}

	if _, err := buf.Read(e.ServerHandshakeTrafficSecret[:]); err != nil {
		return errors.NewEventDecodeError("gotls.ServerHandshakeTrafficSecret", err)
	}

	if _, err := buf.Read(e.ClientAppTrafficSecret[:]); err != nil {
		return errors.NewEventDecodeError("gotls.ClientAppTrafficSecret", err)
	}

	if _, err := buf.Read(e.ServerAppTrafficSecret[:]); err != nil {
		return errors.NewEventDecodeError("gotls.ServerAppTrafficSecret", err)
	}

	if _, err := buf.Read(e.ExporterMasterSecret[:]); err != nil {
		return errors.NewEventDecodeError("gotls.ExporterMasterSecret", err)
	}

	return nil
}

// String returns a human-readable representation of the event.
func (e *MasterSecretEvent) String() string {
	return fmt.Sprintf("PID:%d, TID:%d, ClientRandom:%s",
		e.Pid, e.Tid, hex.EncodeToString(e.ClientRandom[:]))
}

// StringHex returns a hexadecimal representation of the event.
func (e *MasterSecretEvent) StringHex() string {
	return e.String() // Master secrets are already in hex
}

// Clone creates a new instance of the event.
func (e *MasterSecretEvent) Clone() domain.Event {
	return &MasterSecretEvent{}
}

// Type returns the event type (ModuleData for master secret events).
func (e *MasterSecretEvent) Type() domain.EventType {
	return domain.EventTypeModuleData
}

// UUID returns a unique identifier for this event.
func (e *MasterSecretEvent) UUID() string {
	return fmt.Sprintf("%d_%d_%d", e.Pid, e.Tid, e.Timestamp)
}

// Validate checks if the event data is valid.
func (e *MasterSecretEvent) Validate() error {
	// Master secret events are always valid if decoded successfully
	return nil
}

// GetTimestamp returns the event timestamp as time.Time
func (e *MasterSecretEvent) GetTimestamp() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

// GetPid returns the process ID
func (e *MasterSecretEvent) GetPid() uint32 {
	return e.Pid
}

// GetClientRandom returns the client random bytes
func (e *MasterSecretEvent) GetClientRandom() []byte {
	return e.ClientRandom[:]
}

// GetMasterKey returns the TLS 1.2 master key
func (e *MasterSecretEvent) GetMasterKey() []byte {
	return e.MasterKey[:]
}

// GetClientHandshakeTrafficSecret returns the TLS 1.3 client handshake traffic secret
func (e *MasterSecretEvent) GetClientHandshakeTrafficSecret() []byte {
	return e.ClientHandshakeTrafficSecret[:]
}

// GetServerHandshakeTrafficSecret returns the TLS 1.3 server handshake traffic secret
func (e *MasterSecretEvent) GetServerHandshakeTrafficSecret() []byte {
	return e.ServerHandshakeTrafficSecret[:]
}

// GetClientAppTrafficSecret returns the TLS 1.3 client application traffic secret
func (e *MasterSecretEvent) GetClientAppTrafficSecret() []byte {
	return e.ClientAppTrafficSecret[:]
}

// GetServerAppTrafficSecret returns the TLS 1.3 server application traffic secret
func (e *MasterSecretEvent) GetServerAppTrafficSecret() []byte {
	return e.ServerAppTrafficSecret[:]
}

// GetExporterMasterSecret returns the TLS 1.3 exporter master secret
func (e *MasterSecretEvent) GetExporterMasterSecret() []byte {
	return e.ExporterMasterSecret[:]
}
