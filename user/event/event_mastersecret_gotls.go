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
	event_type   EventType
	Lable        [MasterSecretKeyLen]byte `json:"lable"`        // lable name
	ClientRandom [GotlsRandomSize]byte    `json:"clientRandom"` // Client Random
	MasterSecret [EvpMaxMdSize]byte       `json:"masterSecret"` // Master Secret
	payload      string
}

func (this *MasterSecretGotlsEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.Lable); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.MasterSecret); err != nil {
		return
	}
	this.payload = fmt.Sprintf("%s %02x %02x", this.Lable, this.ClientRandom, this.MasterSecret)
	return nil
}

func (this *MasterSecretGotlsEvent) StringHex() string {
	s := fmt.Sprintf("Lable:%s, ClientRandom:%02x", this.Lable, this.ClientRandom)
	return s
}

func (this *MasterSecretGotlsEvent) String() string {
	s := fmt.Sprintf("Lable:%s, ClientRandom:%02x", this.Lable, this.ClientRandom)
	return s
}

func (this *MasterSecretGotlsEvent) Clone() IEventStruct {
	event := new(MasterSecretGotlsEvent)
	event.event_type = EventTypeModuleData
	return event
}

func (this *MasterSecretGotlsEvent) EventType() EventType {
	return this.event_type
}

func (this *MasterSecretGotlsEvent) GetUUID() string {
	return fmt.Sprintf("%02X", this.ClientRandom)
}

func (this *MasterSecretGotlsEvent) Payload() []byte {
	return []byte(this.payload)
}

func (this *MasterSecretGotlsEvent) PayloadLen() int {
	return len(this.payload)
}
