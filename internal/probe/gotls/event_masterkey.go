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
// This structure matches the eBPF event structure: struct mastersecret_gotls_t
type MasterSecretEvent struct {
	Label           [32]byte // label[MASTER_SECRET_KEY_LEN]: TLS key label
	LabelLen        uint8    // labellen: Length of label
	ClientRandom    [64]byte // client_random[EVP_MAX_MD_SIZE]: Client random
	ClientRandomLen uint8    // client_random_len: Length of client random
	Secret          [64]byte // secret_[EVP_MAX_MD_SIZE]: Secret key material
	SecretLen       uint8    // secret_len: Length of secret
}

// DecodeFromBytes deserializes the event from raw eBPF data.
func (e *MasterSecretEvent) DecodeFromBytes(data []byte) error {
	expectedSize := 32 + 1 + 64 + 1 + 64 + 1 // 163 bytes
	if len(data) < expectedSize {
		return errors.NewEventDecodeError("gotls.MasterSecretEvent",
			fmt.Errorf("data too short: got %d bytes, need at least %d", len(data), expectedSize))
	}

	buf := bytes.NewBuffer(data)

	// Read label
	if _, err := buf.Read(e.Label[:]); err != nil {
		return errors.NewEventDecodeError("gotls.Label", err)
	}

	// Read label length
	if err := binary.Read(buf, binary.LittleEndian, &e.LabelLen); err != nil {
		return errors.NewEventDecodeError("gotls.LabelLen", err)
	}

	// Read client random
	if _, err := buf.Read(e.ClientRandom[:]); err != nil {
		return errors.NewEventDecodeError("gotls.ClientRandom", err)
	}

	// Read client random length
	if err := binary.Read(buf, binary.LittleEndian, &e.ClientRandomLen); err != nil {
		return errors.NewEventDecodeError("gotls.ClientRandomLen", err)
	}

	// Read secret
	if _, err := buf.Read(e.Secret[:]); err != nil {
		return errors.NewEventDecodeError("gotls.Secret", err)
	}

	// Read secret length
	if err := binary.Read(buf, binary.LittleEndian, &e.SecretLen); err != nil {
		return errors.NewEventDecodeError("gotls.SecretLen", err)
	}

	return nil
}

// String returns a human-readable representation of the event.
func (e *MasterSecretEvent) String() string {
	label := string(e.Label[:e.LabelLen])
	clientRandomHex := hex.EncodeToString(e.ClientRandom[:e.ClientRandomLen])
	return fmt.Sprintf("Label: %s, ClientRandom: %s",
		label, clientRandomHex)
}

// StringHex returns a hexadecimal representation of the event.
func (e *MasterSecretEvent) StringHex() string {
	label := string(e.Label[:e.LabelLen])
	clientRandom := hex.EncodeToString(e.ClientRandom[:e.ClientRandomLen])
	secret := hex.EncodeToString(e.Secret[:e.SecretLen])
	return fmt.Sprintf("Label:%s, ClientRandom:%s, Secret:%s",
		label, clientRandom, secret)
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
	clientRandom := hex.EncodeToString(e.ClientRandom[:e.ClientRandomLen])
	return fmt.Sprintf("master_secret_%s", clientRandom)
}

// Validate checks if the event data is valid.
func (e *MasterSecretEvent) Validate() error {
	if e.LabelLen > 32 {
		return fmt.Errorf("label length %d exceeds maximum 32", e.LabelLen)
	}
	if e.ClientRandomLen > 64 {
		return fmt.Errorf("client random length %d exceeds maximum 64", e.ClientRandomLen)
	}
	if e.SecretLen > 64 {
		return fmt.Errorf("secret length %d exceeds maximum 64", e.SecretLen)
	}
	return nil
}

// GetTimestamp returns a zero time since master secret events don't have timestamps
func (e *MasterSecretEvent) GetTimestamp() time.Time {
	return time.Time{}
}

// GetPid returns 0 since master secret events don't have PID
func (e *MasterSecretEvent) GetPid() uint32 {
	return 0
}

// GetLabel returns the TLS key label
func (e *MasterSecretEvent) GetLabel() string {
	return string(e.Label[:e.LabelLen])
}

// GetClientRandom returns the client random bytes
func (e *MasterSecretEvent) GetClientRandom() []byte {
	return e.ClientRandom[:e.ClientRandomLen]
}

// GetSecret returns the secret key material
func (e *MasterSecretEvent) GetSecret() []byte {
	return e.Secret[:e.SecretLen]
}

// Compatibility methods for KeylogHandler interface (OpenSSL-style)
// These methods allow GoTLS events to be handled by the unified KeylogHandler

// GetVersion returns 0 for GoTLS (GoTLS uses label-based format, not version-based)
func (e *MasterSecretEvent) GetVersion() int32 {
	return 0
}

// GetMasterKey returns the secret (alias for GetSecret for OpenSSL compatibility)
func (e *MasterSecretEvent) GetMasterKey() []byte {
	return e.GetSecret()
}

// GetCipherId returns 0 (not used in GoTLS keylog format)
func (e *MasterSecretEvent) GetCipherId() uint32 {
	return 0
}

// GetEarlySecret returns empty (GoTLS uses label-based format)
func (e *MasterSecretEvent) GetEarlySecret() []byte {
	return nil
}

// GetHandshakeSecret returns empty (GoTLS uses label-based format)
func (e *MasterSecretEvent) GetHandshakeSecret() []byte {
	return nil
}

// GetHandshakeTrafficHash returns empty (GoTLS uses label-based format)
func (e *MasterSecretEvent) GetHandshakeTrafficHash() []byte {
	return nil
}

// GetClientAppTrafficSecret returns empty (GoTLS uses label-based format)
func (e *MasterSecretEvent) GetClientAppTrafficSecret() []byte {
	return nil
}

// GetServerAppTrafficSecret returns empty (GoTLS uses label-based format)
func (e *MasterSecretEvent) GetServerAppTrafficSecret() []byte {
	return nil
}

// GetExporterMasterSecret returns empty (GoTLS uses label-based format)
func (e *MasterSecretEvent) GetExporterMasterSecret() []byte {
	return nil
}
