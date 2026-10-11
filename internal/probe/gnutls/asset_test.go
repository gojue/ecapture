// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gnutls

import (
	"testing"

	"github.com/gojue/ecapture/v2/internal/probe/bytecode"
)

func TestBytecodeAssetKeys(t *testing.T) {
	for _, tt := range []struct {
		mode bytecode.Mode
		want string
	}{{bytecode.ModeCore, "bytecode/gnutls_3_6_12_kern_core.o"}, {bytecode.ModeNonCore, "bytecode/gnutls_3_6_12_kern_noncore.o"}} {
		got, err := bytecode.AssetName("bytecode/gnutls_3_6_12_kern.o", tt.mode)
		if err != nil {
			t.Fatalf("AssetName() error = %v", err)
		}
		if got != tt.want {
			t.Fatalf("AssetName() = %q, want %q", got, tt.want)
		}
	}
}
