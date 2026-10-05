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
	"testing"

	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
	"github.com/gojue/ecapture/v2/pkg/util/hkdf"
	"github.com/stretchr/testify/require"
)

var _ handlers.GoTLSMasterSecretEvent = (*BoringSSLKeylogEvent)(nil)

func TestBoringSSLKeylogEventDecode(t *testing.T) {
	want := &BoringSSLKeylogEvent{
		LabelLen:        uint8(len(hkdf.KeyLogLabelClientHandshake)),
		ClientRandomLen: Ssl3RandomSize,
		SecretLen:       32,
	}
	copy(want.Label[:], hkdf.KeyLogLabelClientHandshake)
	for i := 0; i < Ssl3RandomSize; i++ {
		want.ClientRandom[i] = byte(i + 1)
		want.Secret[i] = byte(0xa0 + i)
	}

	var encoded bytes.Buffer
	require.NoError(t, binary.Write(&encoded, binary.LittleEndian, want))
	require.Len(t, encoded.Bytes(), boringSSLKeylogEventSize)

	got := &BoringSSLKeylogEvent{}
	require.NoError(t, got.DecodeFromBytes(encoded.Bytes()))
	require.NoError(t, got.Validate())
	require.Equal(t, want.GetLabel(), got.GetLabel())
	require.Equal(t, want.GetClientRandom(), got.GetClientRandom())
	require.Equal(t, want.GetSecret(), got.GetSecret())
}

func TestBoringSSLKeylogEventRejectsInvalidLengths(t *testing.T) {
	event := &BoringSSLKeylogEvent{
		LabelLen:        1,
		ClientRandomLen: Ssl3RandomSize,
		SecretLen:       boringSSLKeylogSecretSize + 1,
	}
	require.Error(t, event.Validate())
}
