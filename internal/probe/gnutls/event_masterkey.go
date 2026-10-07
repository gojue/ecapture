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

package gnutls

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

const (
	Ssl3RandomSize     = handlers.Ssl3RandomSize
	MasterSecretMaxLen = handlers.MasterSecretMaxLen
	EvpMaxMdSize       = handlers.EvpMaxMdSize

	GnuTLSSSL3   = 1
	GnuTLSTLS10  = 2
	GnuTLSTLS11  = 3
	GnuTLSTLS12  = 4
	GnuTLSTLS13  = 5
	GnuTLSDTLS10 = 201
	GnuTLSDTLS12 = 202

	GnuTLSMACSHA256 = 6
	GnuTLSMACSHA384 = 7

	masterSecretEventSize = 4 + Ssl3RandomSize + MasterSecretMaxLen + 4 + 6*EvpMaxMdSize
)

// MasterSecretEvent mirrors struct gnutls_mastersecret_st in
// kern/gnutls_masterkey.h. GnuTLS reports protocol and MAC identifiers using
// its internal enums rather than TLS wire values.
type MasterSecretEvent struct {
	Version                      int32                    `json:"version"`
	ClientRandom                 [Ssl3RandomSize]byte     `json:"clientRandom"`
	MasterKey                    [MasterSecretMaxLen]byte `json:"masterKey"`
	CipherId                     uint32                   `json:"cipherId"`
	ClientEarlyTrafficSecret     [EvpMaxMdSize]byte       `json:"clientEarlyTrafficSecret"`
	ClientHandshakeTrafficSecret [EvpMaxMdSize]byte       `json:"clientHandshakeTrafficSecret"`
	ServerHandshakeTrafficSecret [EvpMaxMdSize]byte       `json:"serverHandshakeTrafficSecret"`
	ClientAppTrafficSecret       [EvpMaxMdSize]byte       `json:"clientAppTrafficSecret"`
	ServerAppTrafficSecret       [EvpMaxMdSize]byte       `json:"serverAppTrafficSecret"`
	ExporterMasterSecret         [EvpMaxMdSize]byte       `json:"exporterMasterSecret"`
}

func (e *MasterSecretEvent) DecodeFromBytes(data []byte) error {
	if len(data) < masterSecretEventSize {
		return errors.New(errors.ErrCodeEventDecode,
			fmt.Sprintf("gnutls master-secret event too short: got %d, need %d", len(data), masterSecretEventSize))
	}

	buf := bytes.NewReader(data)
	fields := []struct {
		name  string
		value any
	}{
		{"Version", &e.Version},
		{"ClientRandom", &e.ClientRandom},
		{"MasterKey", &e.MasterKey},
		{"CipherId", &e.CipherId},
		{"ClientEarlyTrafficSecret", &e.ClientEarlyTrafficSecret},
		{"ClientHandshakeTrafficSecret", &e.ClientHandshakeTrafficSecret},
		{"ServerHandshakeTrafficSecret", &e.ServerHandshakeTrafficSecret},
		{"ClientAppTrafficSecret", &e.ClientAppTrafficSecret},
		{"ServerAppTrafficSecret", &e.ServerAppTrafficSecret},
		{"ExporterMasterSecret", &e.ExporterMasterSecret},
	}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field.value); err != nil {
			return errors.NewEventDecodeError("gnutls.masterSecret."+field.name, err)
		}
	}
	return nil
}

func (e *MasterSecretEvent) String() string {
	return fmt.Sprintf("GnuTLS master secret: version=%d client_random=%x",
		e.Version, e.ClientRandom[:8])
}

func (e *MasterSecretEvent) StringHex() string {
	return e.String()
}

func (e *MasterSecretEvent) Clone() domain.Event {
	clone := *e
	return &clone
}

func (e *MasterSecretEvent) Type() domain.EventType {
	return domain.EventTypeModuleData
}

func (e *MasterSecretEvent) UUID() string {
	return fmt.Sprintf("gnutls_%d_%x", e.Version, e.ClientRandom)
}

func (e *MasterSecretEvent) Validate() error {
	switch e.Version {
	case GnuTLSSSL3, GnuTLSTLS10, GnuTLSTLS11, GnuTLSTLS12, GnuTLSTLS13,
		GnuTLSDTLS10, GnuTLSDTLS12:
	default:
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid GnuTLS protocol version: %d", e.Version))
	}

	if allZero(e.ClientRandom[:]) {
		return errors.New(errors.ErrCodeEventValidation, "client random is all zeros")
	}
	return nil
}

func (e *MasterSecretEvent) IsTLS13() bool {
	return e.Version == GnuTLSTLS13
}

func (e *MasterSecretEvent) GetClientRandom() []byte {
	return e.ClientRandom[:]
}

func (e *MasterSecretEvent) GetMasterKey() []byte {
	return e.MasterKey[:]
}

func (e *MasterSecretEvent) GetTLS13SecretLength() int {
	if e.CipherId == GnuTLSMACSHA384 {
		return 48
	}
	return 32
}

func (e *MasterSecretEvent) GetClientEarlyTrafficSecret() []byte {
	return e.ClientEarlyTrafficSecret[:]
}

func (e *MasterSecretEvent) GetClientHandshakeTrafficSecret() []byte {
	return e.ClientHandshakeTrafficSecret[:]
}

func (e *MasterSecretEvent) GetServerHandshakeTrafficSecret() []byte {
	return e.ServerHandshakeTrafficSecret[:]
}

func (e *MasterSecretEvent) GetClientAppTrafficSecret() []byte {
	return e.ClientAppTrafficSecret[:]
}

func (e *MasterSecretEvent) GetServerAppTrafficSecret() []byte {
	return e.ServerAppTrafficSecret[:]
}

func (e *MasterSecretEvent) GetExporterMasterSecret() []byte {
	return e.ExporterMasterSecret[:]
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
