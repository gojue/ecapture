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
	"testing"
)

func TestSymbolTextOffset(t *testing.T) {
	t.Parallel()

	text := &elf.Section{SectionHeader: elf.SectionHeader{
		Addr:   0x401000,
		Offset: 0x1000,
		Size:   0x28a171,
	}}

	tests := []struct {
		name  string
		entry uint64
		want  uint64
	}{
		{name: "virtual address", entry: 0x5890e0, want: 0x1880e0},
		{name: "Go 1.26 text relative", entry: 0x1880e0, want: 0x1880e0},
		{name: "first text byte", entry: 0x401000, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := symbolTextOffset(tt.entry, text)
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
	if _, err := symbolTextOffset(0x900000, text); err == nil {
		t.Fatal("symbolTextOffset() error = nil, want out-of-range error")
	}
}
