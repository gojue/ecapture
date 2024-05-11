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

package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// openssl_mastersecret_events

const (
	Ssl3RandomSize     = 32
	MasterSecretMaxLen = 48
	EvpMaxMdSize       = 64
)

/*
		u8 client_random[SSL3_RANDOM_SIZE];
	    u8 master_key[MASTER_SECRET_MAX_LEN];
*/
type MasterSecretEvent struct {
	eventType EventType
	Version   int32 `json:"version"` // TLS Version

	// TLS 1.2 or older
	ClientRandom [Ssl3RandomSize]byte     `json:"clientRandom"` // Client Random
	MasterKey    [MasterSecretMaxLen]byte `json:"masterKey"`    // Master Key

	// TLS 1.3
	CipherId               uint32             `json:"cipherId"`               // Cipher ID
	HandshakeSecret        [EvpMaxMdSize]byte `json:"handshakeSecret"`        // Handshake Secret
	HandshakeTrafficHash   [EvpMaxMdSize]byte `json:"handshakeTrafficHash"`   // Handshake Traffic Hash
	ClientAppTrafficSecret [EvpMaxMdSize]byte `json:"clientAppTrafficSecret"` // Client App Traffic Secret
	ServerAppTrafficSecret [EvpMaxMdSize]byte `json:"serverAppTrafficSecret"` // Server App Traffic Secret
	ExporterMasterSecret   [EvpMaxMdSize]byte `json:"exporterMasterSecret"`   // Exporter Master Secret
	payload                string
}

func (mse *MasterSecretEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &mse.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.MasterKey); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.CipherId); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.HandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.HandshakeTrafficHash); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ClientAppTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ServerAppTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ExporterMasterSecret); err != nil {
		return
	}
	mse.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", mse.ClientRandom, mse.MasterKey)
	return nil
}

func (mse *MasterSecretEvent) StringHex() string {
	v := TlsVersion{
		Version: mse.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), mse.ClientRandom)
	return s
}

func (mse *MasterSecretEvent) String() string {
	v := TlsVersion{
		Version: mse.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), mse.ClientRandom)
	return s
}

func (mse *MasterSecretEvent) Clone() IEventStruct {
	event := new(MasterSecretEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (mse *MasterSecretEvent) EventType() EventType {
	return mse.eventType
}

func (mse *MasterSecretEvent) GetUUID() string {
	return fmt.Sprintf("%02X", mse.ClientRandom)
}

func (mse *MasterSecretEvent) Payload() []byte {
	return []byte(mse.payload)
}

func (mse *MasterSecretEvent) PayloadLen() int {
	return len(mse.payload)
}

// MasterSecretBSSLEvent for BoringSSL  TLS 1.3
type MasterSecretBSSLEvent struct {
	eventType EventType
	Version   int32 `json:"version"` // TLS Version

	// TLS 1.2 or older
	ClientRandom [Ssl3RandomSize]byte     `json:"clientRandom"` // Client Random
	Secret       [MasterSecretMaxLen]byte `json:"secret"`       // secret Key

	// TLS 1.3
	HashLen               uint32             `json:"hashLen"`               // hashLen
	EarlyTrafficSecret    [EvpMaxMdSize]byte `json:"earlyTrafficSecret"`    // CLIENT_EARLY_TRAFFIC_SECRET
	ClientHandshakeSecret [EvpMaxMdSize]byte `json:"clientHandshakeSecret"` // CLIENT_HANDSHAKE_TRAFFIC_SECRET
	ServerHandshakeSecret [EvpMaxMdSize]byte `json:"serverHandshakeSecret"` // SERVER_HANDSHAKE_TRAFFIC_SECRET
	ClientTrafficSecret0  [EvpMaxMdSize]byte `json:"clientTrafficSecret0"`  // SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_
	ServerTrafficSecret0  [EvpMaxMdSize]byte `json:"serverTrafficSecret0"`  // SERVER_TRAFFIC_SECRET_0
	ExporterSecret        [EvpMaxMdSize]byte `json:"exporterSecret"`        // EXPORTER_SECRET
	payload               string
}

func (msbe *MasterSecretBSSLEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &msbe.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.Secret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.HashLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.EarlyTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.ClientHandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.ServerHandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.ClientTrafficSecret0); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.ServerTrafficSecret0); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &msbe.ExporterSecret); err != nil {
		return
	}
	msbe.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", msbe.ClientRandom, msbe.Secret)
	return nil
}

func (msbe *MasterSecretBSSLEvent) StringHex() string {
	v := TlsVersion{
		Version: msbe.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), msbe.ClientRandom)
	return s
}

func (msbe *MasterSecretBSSLEvent) String() string {
	v := TlsVersion{
		Version: msbe.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), msbe.ClientRandom)
	return s
}

func (msbe *MasterSecretBSSLEvent) Clone() IEventStruct {
	event := new(MasterSecretBSSLEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (msbe *MasterSecretBSSLEvent) EventType() EventType {
	return msbe.eventType
}

func (msbe *MasterSecretBSSLEvent) GetUUID() string {
	return fmt.Sprintf("%02X", msbe.ClientRandom)
}

func (msbe *MasterSecretBSSLEvent) Payload() []byte {
	return []byte(msbe.payload)
}

func (msbe *MasterSecretBSSLEvent) PayloadLen() int {
	return len(msbe.payload)
}
