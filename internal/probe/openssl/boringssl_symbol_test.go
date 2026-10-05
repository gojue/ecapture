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
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecutableFileOffset(t *testing.T) {
	programs := []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Off: 0x1000, Vaddr: 0x2000, Memsz: 0x100}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0x4000, Vaddr: 0x8000, Memsz: 0x1000}},
	}

	offset, err := executableFileOffset(programs, 0x8123)
	require.NoError(t, err)
	require.Equal(t, uint64(0x4123), offset)
}

func TestExecutableFileOffsetRejectsNonExecutableAddress(t *testing.T) {
	programs := []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Off: 0x1000, Vaddr: 0x2000, Memsz: 0x100}},
	}

	_, err := executableFileOffset(programs, 0x2020)
	require.Error(t, err)
}
