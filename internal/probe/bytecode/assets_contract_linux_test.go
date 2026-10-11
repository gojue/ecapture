//go:build ebpfassets && !ecap_android

// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bytecode

func probeAssetContracts() []probeAssetContract {
	return []probeAssetContract{
		{probe: "openssl", baseName: "bytecode/openssl_1_1_1j_kern.o"},
		{probe: "gotls", baseName: "bytecode/gotls_kern.o"},
		{probe: "gnutls", baseName: "bytecode/gnutls_3_6_12_kern.o"},
		{probe: "nspr", baseName: "bytecode/nspr_kern.o"},
		{probe: "bash", baseName: "bytecode/bash_kern.o"},
		{probe: "zsh", baseName: "bytecode/zsh_kern.o"},
		{probe: "mysql", baseName: "bytecode/mysqld_kern.o"},
		// Keep this exact base name so non-CO-RE resolution is permanently
		// asserted as bytecode/postgres_kern_noncore.o.
		{probe: "postgres", baseName: "bytecode/postgres_kern.o"},
	}
}
