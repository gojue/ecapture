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
	SSL3_RANDOM_SIZE      = 32
	MASTER_SECRET_MAX_LEN = 48
	EVP_MAX_MD_SIZE       = 64
)

/*
	u8 client_random[SSL3_RANDOM_SIZE];
    u8 master_key[MASTER_SECRET_MAX_LEN];
*/
type MasterSecretEvent struct {
	event_type EventType
	Version    int32 `json:"version"` // TLS Version

	// TLS 1.2 or older
	ClientRandom [SSL3_RANDOM_SIZE]byte      `json:"clientRandom"` // Client Random
	MasterKey    [MASTER_SECRET_MAX_LEN]byte `json:"masterKey"`    // Master Key

	// TLS 1.3
	CipherId             uint32                `json:"cipherId"`             // Cipher ID
	HandshakeSecret      [EVP_MAX_MD_SIZE]byte `json:"handshakeSecret"`      // Handshake Secret
	MasterSecret         [EVP_MAX_MD_SIZE]byte `json:"masterSecret"`         // Master Secret
	ServerFinishedHash   [EVP_MAX_MD_SIZE]byte `json:"serverFinishedHash"`   // Server Finished Hash
	HandshakeTrafficHash [EVP_MAX_MD_SIZE]byte `json:"handshakeTrafficHash"` // Handshake Traffic Hash
	ExporterMasterSecret [EVP_MAX_MD_SIZE]byte `json:"exporterMasterSecret"` // Exporter Master Secret
	payload              string
}

func (this *MasterSecretEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.MasterKey); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.CipherId); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.HandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.MasterSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ServerFinishedHash); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.HandshakeTrafficHash); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ExporterMasterSecret); err != nil {
		return
	}
	this.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", this.ClientRandom, this.MasterKey)
	return nil
}

func (this *MasterSecretEvent) StringHex() string {
	v := TlsVersion{
		Version: this.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), this.ClientRandom)
	return s
}

func (this *MasterSecretEvent) String() string {
	v := TlsVersion{
		Version: this.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), this.ClientRandom)
	return s
}

func (this *MasterSecretEvent) Clone() IEventStruct {
	event := new(MasterSecretEvent)
	event.event_type = EventTypeModuleData
	return event
}

func (this *MasterSecretEvent) EventType() EventType {
	return this.event_type
}

func (this *MasterSecretEvent) GetUUID() string {
	return fmt.Sprintf("%02X", this.ClientRandom)
}

func (this *MasterSecretEvent) Payload() []byte {
	return []byte(this.payload)
}

func (this *MasterSecretEvent) PayloadLen() int {
	return len(this.payload)
}
