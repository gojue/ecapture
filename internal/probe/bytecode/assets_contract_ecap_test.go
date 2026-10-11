//go:build ebpfassets && ecap_android

// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bytecode

func probeAssetContracts() []probeAssetContract {
	return []probeAssetContract{
		{probe: "boringssl", baseName: "bytecode/boringssl_a_13_kern.o"},
		{probe: "gotls", baseName: "bytecode/gotls_kern.o"},
		{probe: "bash", baseName: "bytecode/bash_kern.o"},
	}
}
