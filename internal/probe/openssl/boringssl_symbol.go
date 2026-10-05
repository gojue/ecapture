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
	"debug/elf"
	"fmt"
	"io"

	"github.com/ulikunitz/xz"
)

const (
	boringSSLKeylogSymbol = "_ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE"
	maxMiniDebugInfoSize  = 32 << 20
)

// findBoringSSLKeylogAddress resolves BoringSSL's internal ssl_log_secret
// function from Android's XZ-compressed .gnu_debugdata symbol table. The
// returned value is a file offset suitable for UprobeOptions.Address.
func findBoringSSLKeylogAddress(path string) (uint64, error) {
	lib, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open BoringSSL ELF: %w", err)
	}
	defer func() {
		_ = lib.Close()
	}()

	section := lib.Section(".gnu_debugdata")
	if section == nil {
		return 0, fmt.Errorf("BoringSSL ELF has no .gnu_debugdata section")
	}
	compressed, err := section.Data()
	if err != nil {
		return 0, fmt.Errorf("read .gnu_debugdata: %w", err)
	}

	reader, err := xz.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return 0, fmt.Errorf("open .gnu_debugdata XZ stream: %w", err)
	}
	var decompressed bytes.Buffer
	if _, err := io.Copy(&decompressed, io.LimitReader(reader, maxMiniDebugInfoSize+1)); err != nil {
		return 0, fmt.Errorf("decompress .gnu_debugdata: %w", err)
	}
	if decompressed.Len() > maxMiniDebugInfoSize {
		return 0, fmt.Errorf("decompressed .gnu_debugdata exceeds %d bytes", maxMiniDebugInfoSize)
	}

	miniDebug, err := elf.NewFile(bytes.NewReader(decompressed.Bytes()))
	if err != nil {
		return 0, fmt.Errorf("parse .gnu_debugdata ELF: %w", err)
	}
	defer func() {
		_ = miniDebug.Close()
	}()

	symbols, err := miniDebug.Symbols()
	if err != nil {
		return 0, fmt.Errorf("read .gnu_debugdata symbols: %w", err)
	}
	for _, symbol := range symbols {
		if symbol.Name != boringSSLKeylogSymbol || elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
			continue
		}
		return executableFileOffset(lib.Progs, symbol.Value)
	}

	return 0, fmt.Errorf("BoringSSL keylog symbol %q not found", boringSSLKeylogSymbol)
}

func executableFileOffset(programs []*elf.Prog, virtualAddress uint64) (uint64, error) {
	for _, program := range programs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 {
			continue
		}
		if program.Vaddr <= virtualAddress && virtualAddress < program.Vaddr+program.Memsz {
			return virtualAddress - program.Vaddr + program.Off, nil
		}
	}
	return 0, fmt.Errorf("symbol address %#x is outside executable load segments", virtualAddress)
}
