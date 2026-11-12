// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package openssl

import (
	"encoding/binary"
	"testing"
)

func TestMasterSecretDTLS12(t *testing.T) {
	data := make([]byte, 4+Ssl3RandomSize+MasterSecretMaxLen)
	binary.LittleEndian.PutUint32(data, 0xfefd)
	data[4], data[4+Ssl3RandomSize] = 1, 2
	zeroRandom := append([]byte(nil), data...)
	clear(zeroRandom[4 : 4+Ssl3RandomSize])
	for _, test := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"dtls12", data, true},
		{"padded", append(append([]byte(nil), data...), make([]byte, 8)...), true},
		{"short", data[:len(data)-1], false},
		{"empty", nil, false},
		{"zero client random", zeroRandom, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			event, err := (&MasterSecretEvent{}).Decode(test.data)
			if (err == nil) != test.valid {
				t.Fatalf("Decode error = %v, valid = %v", err, test.valid)
			}
			if test.valid {
				secret := event.(*MasterSecretEvent)
				if secret.Version != 0xfefd || secret.ClientRandom[0] != 1 || secret.MasterKey[0] != 2 {
					t.Fatal("DTLS event fields were not preserved")
				}
			}
		})
	}
	binary.LittleEndian.PutUint32(data, 0xfefc)
	if _, err := (&MasterSecretEvent{}).Decode(data); err == nil {
		t.Fatal("unsupported DTLS version accepted")
	}
}
