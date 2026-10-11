// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bash

import (
	"testing"

	"github.com/gojue/ecapture/v2/internal/probe/bytecode"
)

func TestBytecodeAssetKeys(t *testing.T) {
	assertAssetKeys(t, "bytecode/bash_kern.o", "bytecode/bash_kern_core.o", "bytecode/bash_kern_noncore.o")
}

func assertAssetKeys(t *testing.T, baseName, coreName, nonCoreName string) {
	t.Helper()
	for _, tt := range []struct {
		mode bytecode.Mode
		want string
	}{{bytecode.ModeCore, coreName}, {bytecode.ModeNonCore, nonCoreName}} {
		got, err := bytecode.AssetName(baseName, tt.mode)
		if err != nil {
			t.Fatalf("AssetName(%q, %s) error = %v", baseName, tt.mode, err)
		}
		if got != tt.want {
			t.Fatalf("AssetName(%q, %s) = %q, want %q", baseName, tt.mode, got, tt.want)
		}
	}
}
