// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package zsh

import (
	"testing"

	"github.com/gojue/ecapture/v2/internal/probe/bytecode"
)

func TestBytecodeAssetKeys(t *testing.T) {
	for _, tt := range []struct {
		mode bytecode.Mode
		want string
	}{{bytecode.ModeCore, "bytecode/zsh_kern_core.o"}, {bytecode.ModeNonCore, "bytecode/zsh_kern_noncore.o"}} {
		got, err := bytecode.AssetName("bytecode/zsh_kern.o", tt.mode)
		if err != nil {
			t.Fatalf("AssetName() error = %v", err)
		}
		if got != tt.want {
			t.Fatalf("AssetName() = %q, want %q", got, tt.want)
		}
	}
}
