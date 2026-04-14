//go:build ecap_android
// +build ecap_android

// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package openssl

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"os"
	"runtime"
	"strings"
)

// PACInfo holds the results of ARM64 Pointer Authentication Code detection.
type PACInfo struct {
	// CPUSupport indicates whether the CPU supports PAC (paca or pacg feature flags).
	CPUSupport bool
	// LibraryPAC indicates whether the target SSL library was compiled with PAC support.
	LibraryPAC bool
	// Detected is true when PAC is likely active (CPU supports it on ARM64).
	Detected bool
}

// GNU_PROPERTY_AARCH64_FEATURE_1_PAC is the ELF property flag indicating
// that an AArch64 binary was compiled with pointer authentication.
// Defined in the AArch64 ELF ABI: https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
const gnuPropertyAarch64Feature1PAC = 0x2

// gnuPropertyAarch64Feature1And is the ELF note property type for AArch64 feature flags.
const gnuPropertyAarch64Feature1And = 0xc0000001

// DetectPACInfo detects ARM64 Pointer Authentication Code (PAC) status.
// It checks CPU feature flags and optionally the target SSL library's ELF properties.
// On non-ARM64 architectures, all fields are false (PAC is ARM64-specific).
func DetectPACInfo(libsslPath string) PACInfo {
	if runtime.GOARCH != "arm64" {
		return PACInfo{}
	}

	info := PACInfo{}
	info.CPUSupport = detectCPUPAC()
	info.Detected = info.CPUSupport
	if libsslPath != "" {
		info.LibraryPAC = detectLibraryPAC(libsslPath)
	}
	return info
}

// detectCPUPAC checks /proc/cpuinfo for PAC feature flags (paca or pacg).
func detectCPUPAC() bool {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Features") {
			continue
		}
		// Line format: "Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp paca pacg ..."
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		features := strings.Fields(line[colonIdx+1:])
		for _, f := range features {
			if f == "paca" || f == "pacg" {
				return true
			}
		}
	}
	return false
}

// detectLibraryPAC checks the ELF .note.gnu.property section of the given
// shared library for the GNU_PROPERTY_AARCH64_FEATURE_1_PAC flag.
func detectLibraryPAC(path string) bool {
	ef, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = ef.Close() }()

	section := ef.Section(".note.gnu.property")
	if section == nil {
		return false
	}

	data, err := section.Data()
	if err != nil {
		return false
	}

	// .note.gnu.property is a sequence of ELF note entries, each containing
	// an array of property descriptors. We use little-endian byte order for
	// AArch64 Linux targets.
	bo := binary.LittleEndian
	// Parse the ELF note header: namesz, descsz, type
	// Then parse the property entries within the desc payload.
	offset := 0
	for offset+12 <= len(data) {
		namesz := int(bo.Uint32(data[offset:]))
		descsz := int(bo.Uint32(data[offset+4:]))
		noteType := bo.Uint32(data[offset+8:])
		offset += 12

		// Align namesz to 4 bytes
		nameEnd := offset + ((namesz + 3) &^ 3)
		descStart := nameEnd
		descEnd := descStart + descsz

		if noteType == 5 /* NT_GNU_PROPERTY_TYPE_0 */ && namesz == 4 &&
			descEnd <= len(data) && string(data[offset:offset+4]) == "GNU\x00" {
			// Parse property entries within this note's desc
			pos := descStart
			for pos+8 <= descEnd {
				propType := bo.Uint32(data[pos:])
				propDataSz := int(bo.Uint32(data[pos+4:]))
				pos += 8
				propDataEnd := pos + propDataSz
				if propDataEnd > descEnd {
					break
				}
				if propType == gnuPropertyAarch64Feature1And && propDataSz >= 4 {
					flags := bo.Uint32(data[pos:])
					if flags&gnuPropertyAarch64Feature1PAC != 0 {
						return true
					}
				}
				// Align to 8 bytes
				pos = (propDataEnd + 7) &^ 7
			}
		}

		// Advance to next note, aligning descsz to 4 bytes
		offset = descStart + ((descsz + 3) &^ 3)
	}
	return false
}
