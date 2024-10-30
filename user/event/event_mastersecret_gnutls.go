// Author: yuweizzz <yuwei764969238@gmail.com>.
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

const (
	GnutlsMasterSize  = 48
	GnutlsRandomSize  = 32
	GnutlsMaxHashSize = 64
)

// mastersecret_gnutls_events
type MasterSecretGnutlsEvent struct {
	eventType             EventType
	Version               int32                   `json:"version"`
	ClientRandom          [GnutlsRandomSize]byte  `json:"clientRandom"`
	MasterSecret          [GnutlsMasterSize]byte  `json:"masterSecret"`
	CipherId              int32                   `json:"cipherId"` // PRF MAC
	ClientHandshakeSecret [GnutlsMaxHashSize]byte `json:"clientHandshakeSecret"`
	ServerHandshakeSecret [GnutlsMaxHashSize]byte `json:"serverHandshakeSecret"`
	ClientTrafficSecret   [GnutlsMaxHashSize]byte `json:"clientTrafficSecret"`
	ServerTrafficSecret   [GnutlsMaxHashSize]byte `json:"serverTrafficSecret"`
	ExporterMasterSecret  [GnutlsMaxHashSize]byte `json:"exporterMasterSecret"`
	payload               string
}

func (mse *MasterSecretGnutlsEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &mse.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.MasterSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.CipherId); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ClientHandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ServerHandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ClientTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ServerTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mse.ExporterMasterSecret); err != nil {
		return
	}
	mse.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", mse.ClientRandom, mse.MasterSecret)
	return nil
}

func (mse *MasterSecretGnutlsEvent) StringHex() string {
	s := fmt.Sprintf("ClientRandom: %02x, MasterSecret: %02x", mse.ClientRandom[0:GnutlsRandomSize], mse.MasterSecret[0:GnutlsMasterSize])
	return s
}

func (mse *MasterSecretGnutlsEvent) String() string {
	s := fmt.Sprintf("ClientRandom: %02x, MasterSecret: %02x", mse.ClientRandom[0:GnutlsRandomSize], mse.MasterSecret[0:GnutlsMasterSize])
	return s
}

func (mse *MasterSecretGnutlsEvent) Clone() IEventStruct {
	event := new(MasterSecretGnutlsEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (mse *MasterSecretGnutlsEvent) EventType() EventType {
	return mse.eventType
}

func (mse *MasterSecretGnutlsEvent) GetUUID() string {
	return fmt.Sprintf("%02X", mse.ClientRandom)
}

func (mse *MasterSecretGnutlsEvent) Payload() []byte {
	return []byte(mse.payload)
}

func (mse *MasterSecretGnutlsEvent) PayloadLen() int {
	return len(mse.payload)
}
