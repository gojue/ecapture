//go:build ebpfassets

// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bytecode

import (
	"testing"

	"github.com/gojue/ecapture/v2/assets"
	"github.com/gojue/ecapture/v2/internal/config"
)

func TestEmbeddedProbeAssetContracts(t *testing.T) {
	assetMode, err := config.EmbeddedByteCodeFileMode()
	if err != nil {
		t.Fatalf("EmbeddedByteCodeFileMode() error = %v", err)
	}
	embedded := make(map[string]bool, len(assets.AssetNames()))
	for _, name := range assets.AssetNames() {
		embedded[name] = true
	}

	for _, contract := range probeAssetContracts() {
		t.Run(contract.probe, func(t *testing.T) {
			for _, mode := range []Mode{ModeCore, ModeNonCore} {
				name, nameErr := AssetName(contract.baseName, mode)
				if nameErr != nil {
					t.Fatalf("AssetName() error = %v", nameErr)
				}
				wantEmbedded := assetModeContains(assetMode, mode)
				if embedded[name] != wantEmbedded {
					t.Fatalf(
						"asset %q embedded=%v, want %v for linked mode %q",
						name,
						embedded[name],
						wantEmbedded,
						config.ByteCodeFileModeName(assetMode),
					)
				}
				if wantEmbedded {
					if _, assetErr := assets.Asset(name); assetErr != nil {
						t.Fatalf("Asset(%q) error = %v", name, assetErr)
					}
				}
			}
		})
	}
}

type probeAssetContract struct {
	probe    string
	baseName string
}
