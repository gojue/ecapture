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

// gotls_mastersecret_events

const (
	GotlsRandomSize    = 32
	MasterSecretKeyLen = 32
)

type MasterSecretGotlsEvent struct {
	eventType       EventType
	Label           [MasterSecretKeyLen]byte `json:"label"` // label name
	LabelLen        uint8                    `json:"labelLen"`
	ClientRandom    [EvpMaxMdSize]byte       `json:"clientRandom"` // Client Random
	ClientRandomLen uint8                    `json:"clientRandomLen"`
	MasterSecret    [EvpMaxMdSize]byte       `json:"masterSecret"` // Master Secret
	MasterSecretLen uint8                    `json:"masterSecretLen"`
	payload         string
}

func (mge *MasterSecretGotlsEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &mge.Label); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mge.LabelLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mge.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mge.ClientRandomLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mge.MasterSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &mge.MasterSecretLen); err != nil {
		return
	}
	if int(mge.LabelLen) > len(mge.Label) {
		return fmt.Errorf("invalid label length, LablenLen:%d, len(Label):%d", mge.LabelLen, len(mge.Label))
	}
	if int(mge.ClientRandomLen) > len(mge.ClientRandom) {
		return fmt.Errorf("invalid label length, ClientRandomLen:%d, len(ClientRandom):%d", mge.ClientRandomLen, len(mge.ClientRandom))
	}
	if int(mge.MasterSecretLen) > len(mge.MasterSecret) {
		return fmt.Errorf("invalid label length, MasterSecretLen:%d, len(MasterSecret):%d", mge.MasterSecretLen, len(mge.MasterSecret))
	}
	mge.payload = fmt.Sprintf("%s %02x %02x", mge.Label, mge.ClientRandom, mge.MasterSecret)
	return nil
}

func (mge *MasterSecretGotlsEvent) StringHex() string {
	s := fmt.Sprintf("Label%s, ClientRandom:%02x, secret:%02x", mge.Label[0:mge.LabelLen], mge.ClientRandom[0:mge.ClientRandomLen], mge.MasterSecret[0:mge.MasterSecretLen])
	return s
}

func (mge *MasterSecretGotlsEvent) String() string {
	s := fmt.Sprintf("Label:%s, ClientRandom:%02x, secret:%02x", mge.Label[0:mge.LabelLen], mge.ClientRandom[0:mge.ClientRandomLen], mge.MasterSecret[0:mge.MasterSecretLen])
	return s
}

func (mge *MasterSecretGotlsEvent) Clone() IEventStruct {
	event := new(MasterSecretGotlsEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (mge *MasterSecretGotlsEvent) EventType() EventType {
	return mge.eventType
}

func (mge *MasterSecretGotlsEvent) GetUUID() string {
	return fmt.Sprintf("%02X", mge.ClientRandom)
}

func (mge *MasterSecretGotlsEvent) Payload() []byte {
	return []byte(mge.payload)
}

func (mge *MasterSecretGotlsEvent) PayloadLen() int {
	return len(mge.payload)
}
