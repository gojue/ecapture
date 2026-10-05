// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
)

const (
	boringSSLKeylogLabelSize  = 32
	boringSSLKeylogRandomSize = 64
	boringSSLKeylogSecretSize = 64
	boringSSLKeylogEventSize  = boringSSLKeylogLabelSize + 1 + boringSSLKeylogRandomSize + 1 + boringSSLKeylogSecretSize + 1
)

// BoringSSLKeylogEvent is emitted at BoringSSL's internal ssl_log_secret
// entrypoint. It uses the same label-based shape as Go's KeyLogWriter events.
type BoringSSLKeylogEvent struct {
	Label           [boringSSLKeylogLabelSize]byte
	LabelLen        uint8
	ClientRandom    [boringSSLKeylogRandomSize]byte
	ClientRandomLen uint8
	Secret          [boringSSLKeylogSecretSize]byte
	SecretLen       uint8
}

func (e *BoringSSLKeylogEvent) DecodeFromBytes(data []byte) error {
	if len(data) < boringSSLKeylogEventSize {
		return errors.NewEventDecodeError("boringssl.KeylogEvent",
			fmt.Errorf("data too short: got %d bytes, need at least %d", len(data), boringSSLKeylogEventSize))
	}

	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, e); err != nil {
		return errors.NewEventDecodeError("boringssl.KeylogEvent", err)
	}
	return nil
}

func (e *BoringSSLKeylogEvent) String() string {
	return fmt.Sprintf("Label: %s, ClientRandom: %x", e.GetLabel(), e.GetClientRandom())
}

func (e *BoringSSLKeylogEvent) StringHex() string {
	return fmt.Sprintf("Label: %s, ClientRandom: %x, Secret: %x",
		e.GetLabel(), e.GetClientRandom(), e.GetSecret())
}

func (e *BoringSSLKeylogEvent) Clone() domain.Event {
	clone := *e
	return &clone
}

func (e *BoringSSLKeylogEvent) Type() domain.EventType {
	return domain.EventTypeModuleData
}

func (e *BoringSSLKeylogEvent) UUID() string {
	return fmt.Sprintf("bssl_keylog_%s_%x", e.GetLabel(), e.GetClientRandom())
}

func (e *BoringSSLKeylogEvent) Validate() error {
	if e.LabelLen == 0 || int(e.LabelLen) > len(e.Label) {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid BoringSSL keylog label length: %d", e.LabelLen))
	}
	if int(e.ClientRandomLen) != Ssl3RandomSize {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid BoringSSL client random length: %d", e.ClientRandomLen))
	}
	if e.SecretLen == 0 || int(e.SecretLen) > len(e.Secret) {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid BoringSSL keylog secret length: %d", e.SecretLen))
	}
	return nil
}

func (e *BoringSSLKeylogEvent) GetLabel() string {
	return string(e.Label[:e.LabelLen])
}

func (e *BoringSSLKeylogEvent) GetClientRandom() []byte {
	return e.ClientRandom[:e.ClientRandomLen]
}

func (e *BoringSSLKeylogEvent) GetSecret() []byte {
	return e.Secret[:e.SecretLen]
}
