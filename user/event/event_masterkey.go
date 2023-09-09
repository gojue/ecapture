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

func (me *MasterSecretEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &me.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.MasterKey); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.CipherId); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.HandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.HandshakeTrafficHash); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ClientAppTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ServerAppTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ExporterMasterSecret); err != nil {
		return
	}
	me.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", me.ClientRandom, me.MasterKey)
	return nil
}

func (me *MasterSecretEvent) StringHex() string {
	v := TlsVersion{
		Version: me.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), me.ClientRandom)
	return s
}

func (me *MasterSecretEvent) String() string {
	v := TlsVersion{
		Version: me.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), me.ClientRandom)
	return s
}

func (me *MasterSecretEvent) Clone() IEventStruct {
	event := new(MasterSecretEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (me *MasterSecretEvent) EventType() EventType {
	return me.eventType
}

func (me *MasterSecretEvent) GetUUID() string {
	return fmt.Sprintf("%02X", me.ClientRandom)
}

func (me *MasterSecretEvent) Payload() []byte {
	return []byte(me.payload)
}

func (me *MasterSecretEvent) PayloadLen() int {
	return len(me.payload)
}

// for BoringSSL  TLS 1.3
type MasterSecretBSSLEvent struct {
	event_type EventType
	Version    int32 `json:"version"` // TLS Version

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

func (this *MasterSecretBSSLEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.Secret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.HashLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.EarlyTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ClientHandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ServerHandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ClientTrafficSecret0); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ServerTrafficSecret0); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ExporterSecret); err != nil {
		return
	}
	this.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", this.ClientRandom, this.Secret)
	return nil
}

func (this *MasterSecretBSSLEvent) StringHex() string {
	v := TlsVersion{
		Version: this.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), this.ClientRandom)
	return s
}

func (this *MasterSecretBSSLEvent) String() string {
	v := TlsVersion{
		Version: this.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), this.ClientRandom)
	return s
}

func (this *MasterSecretBSSLEvent) Clone() IEventStruct {
	event := new(MasterSecretBSSLEvent)
	event.event_type = EventTypeModuleData
	return event
}

func (this *MasterSecretBSSLEvent) EventType() EventType {
	return this.event_type
}

func (this *MasterSecretBSSLEvent) GetUUID() string {
	return fmt.Sprintf("%02X", this.ClientRandom)
}

func (this *MasterSecretBSSLEvent) Payload() []byte {
	return []byte(this.payload)
}

func (this *MasterSecretBSSLEvent) PayloadLen() int {
	return len(this.payload)
}
