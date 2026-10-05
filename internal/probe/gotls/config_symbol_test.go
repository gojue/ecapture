// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package gotls

import (
	"debug/elf"
	"encoding/binary"
	"testing"
)

func TestSymbolTextOffset(t *testing.T) {
	t.Parallel()

	text := &elf.Section{SectionHeader: elf.SectionHeader{
		Addr:   0x401000,
		Offset: 0x1000,
		Size:   0x800000,
	}}

	tests := []struct {
		name  string
		entry uint64
		mode  symbolEntryMode
		want  uint64
	}{
		{name: "virtual address", entry: 0x5890e0, mode: symbolEntryVirtualAddress, want: 0x1880e0},
		{name: "text relative", entry: 0x1880e0, mode: symbolEntryTextRelative, want: 0x1880e0},
		{name: "overlapping relative address", entry: 0x500000, mode: symbolEntryTextRelative, want: 0x500000},
		{name: "same value as virtual address", entry: 0x500000, mode: symbolEntryVirtualAddress, want: 0xff000},
		{name: "first virtual text byte", entry: 0x401000, mode: symbolEntryVirtualAddress, want: 0},
		{name: "first relative text byte", entry: 0, mode: symbolEntryTextRelative, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := symbolTextOffset(tt.entry, text, tt.mode)
			if err != nil {
				t.Fatalf("symbolTextOffset() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("symbolTextOffset() = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestSymbolTextOffsetRejectsOutOfRangeEntry(t *testing.T) {
	t.Parallel()

	text := &elf.Section{SectionHeader: elf.SectionHeader{
		Addr: 0x401000,
		Size: 0x1000,
	}}
	if _, err := symbolTextOffset(0x900000, text, symbolEntryVirtualAddress); err == nil {
		t.Fatal("symbolTextOffset() error = nil, want out-of-range error")
	}
}

func TestPclnUsesRelativeFunctionOffsets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		magic uint32
		want  bool
	}{
		{name: "Go 1.12", magic: go12PCLnTabMagic, want: false},
		{name: "Go 1.16", magic: go116PCLnTabMagic, want: false},
		{name: "Go 1.18", magic: go118PCLnTabMagic, want: true},
		{name: "Go 1.20 and newer", magic: go120PCLnTabMagic, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 4)
			binary.LittleEndian.PutUint32(data, tt.magic)
			if got := pclnUsesRelativeFunctionOffsets(data); got != tt.want {
				t.Fatalf("pclnUsesRelativeFunctionOffsets() = %t, want %t", got, tt.want)
			}
		})
	}
}
