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
	"testing"

	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

func TestEventDecodeFromBytes(t *testing.T) {
	var data [MaxDataSize]byte
	copy(data[:], "ECAPTURE_GNUTLS")
	var comm [TaskCommLen]byte
	copy(comm[:], "gnutls-client")

	sample := encodeFields(t,
		int64(DataTypeWrite), uint64(123), uint32(42), uint32(43),
		data, int32(len("ECAPTURE_GNUTLS")), comm,
	)
	sample = append(sample, 0xaa, 0xbb, 0xcc, 0xdd)

	event, err := (&gnutlsEventDecoder{}).Decode(nil, sample)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	got := event.(*Event)
	if string(got.GetData()) != "ECAPTURE_GNUTLS" {
		t.Fatalf("GetData() = %q", got.GetData())
	}
	if got.GetComm() != "gnutls-client" {
		t.Fatalf("GetComm() = %q", got.GetComm())
	}
	if got.PerfMonoNs() != 123 {
		t.Fatalf("PerfMonoNs() = %d", got.PerfMonoNs())
	}
}

func TestEventDecodeRejectsShortAndMalformedSamples(t *testing.T) {
	if err := (&Event{}).DecodeFromBytes(make([]byte, tlsDataEventSize-1)); err == nil {
		t.Fatal("short sample decoded without error")
	}

	var data [MaxDataSize]byte
	var comm [TaskCommLen]byte
	sample := encodeFields(t,
		int64(99), uint64(1), uint32(2), uint32(3), data, int32(MaxDataSize+1), comm,
	)
	if _, err := (&gnutlsEventDecoder{}).Decode(nil, sample); err == nil {
		t.Fatal("malformed sample decoded without error")
	}
}

func TestMasterSecretEventDecodeTLS13(t *testing.T) {
	var random [Ssl3RandomSize]byte
	var master [MasterSecretMaxLen]byte
	var early, clientHandshake, serverHandshake [EvpMaxMdSize]byte
	var clientTraffic, serverTraffic, exporter [EvpMaxMdSize]byte
	fillBytes(random[:], 1)
	fillBytes(early[:], 2)
	fillBytes(clientHandshake[:], 3)
	fillBytes(serverHandshake[:], 4)
	fillBytes(clientTraffic[:], 5)
	fillBytes(serverTraffic[:], 6)
	fillBytes(exporter[:], 7)

	sample := encodeFields(t,
		int32(GnuTLSTLS13), random, master, uint32(GnuTLSMACSHA384),
		early, clientHandshake, serverHandshake, clientTraffic, serverTraffic, exporter,
	)
	sample = append(sample, make([]byte, 8)...)

	event, err := (&masterSecretEventDecoder{}).Decode(nil, sample)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	got := event.(*MasterSecretEvent)
	if !got.IsTLS13() || got.GetTLS13SecretLength() != 48 {
		t.Fatalf("TLS 1.3 metadata = (%v, %d)", got.IsTLS13(), got.GetTLS13SecretLength())
	}
	if got.GetClientHandshakeTrafficSecret()[0] != 3 || got.GetServerHandshakeTrafficSecret()[0] != 4 {
		t.Fatal("handshake traffic secrets decoded at the wrong offsets")
	}
	var _ handlers.DirectTrafficSecretEvent = got
}

func TestMasterSecretEventRejectsShortSample(t *testing.T) {
	if err := (&MasterSecretEvent{}).DecodeFromBytes(make([]byte, masterSecretEventSize-1)); err == nil {
		t.Fatal("short master-secret sample decoded without error")
	}
}

func TestPacketEventDecode(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	var comm [TaskCommLen]byte
	copy(comm[:], "gnutls-client")
	sample := encodeFields(t,
		uint64(100), uint32(10), comm, uint32(len(payload)), uint32(2), payload,
	)

	event, err := (&packetEventDecoder{}).Decode(nil, sample)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	got := event.(*PacketEvent)
	if !bytes.Equal(got.GetPacketData(), payload) {
		t.Fatalf("packet data = %v", got.GetPacketData())
	}
}

func TestPacketEventRejectsTruncatedPayload(t *testing.T) {
	var comm [TaskCommLen]byte
	sample := encodeFields(t,
		uint64(100), uint32(10), comm, uint32(100), uint32(2), []byte{1, 2},
	)
	if err := (&PacketEvent{}).DecodeFromBytes(sample); err == nil {
		t.Fatal("truncated packet decoded without error")
	}
}

func encodeFields(t *testing.T, fields ...any) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, field := range fields {
		if err := binary.Write(&buf, binary.LittleEndian, field); err != nil {
			t.Fatalf("binary.Write(%T): %v", field, err)
		}
	}
	return buf.Bytes()
}

func fillBytes(data []byte, value byte) {
	for i := range data {
		data[i] = value
	}
}
