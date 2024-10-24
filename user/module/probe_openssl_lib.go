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

package module

import (
	"debug/elf"
	"fmt"
	"github.com/gojue/ecapture/user/config"
	"os"
	"regexp"
	"strings"
)

const (
	Linuxdefaulefilename102 = "linux_default_1_0_2"
	Linuxdefaulefilename110 = "linux_default_1_1_0"
	Linuxdefaulefilename111 = "linux_default_1_1_1"
	Linuxdefaulefilename30  = "linux_default_3_0"
	Linuxdefaulefilename31  = "linux_default_3_0"
	Linuxdefaulefilename320 = "linux_default_3_2"
	Linuxdefaulefilename330 = "linux_default_3_3"
	AndroidDefauleFilename  = "android_default"

	OpenSslVersionLen = 30 // openssl version string length
)

const (
	MaxSupportedOpenSSL102Version = 'u'
	MaxSupportedOpenSSL110Version = 'l'
	MaxSupportedOpenSSL111Version = 'w'
	MaxSupportedOpenSSL30Version  = 15
	MaxSupportedOpenSSL31Version  = 7
	SupportedOpenSSL32Version2    = 2 // openssl 3.2.0 ~ 3.2.2
	MaxSupportedOpenSSL32Version  = 3 // openssl 3.2.3 ~ newer
	SupportedOpenSSL33Version1    = 1 // openssl 3.3.0 ~ 3.3.1
	MaxSupportedOpenSSL33Version  = 2 // openssl 3.3.2
)

// initOpensslOffset initial BpfMap
func (m *MOpenSSLProbe) initOpensslOffset() {
	m.sslVersionBpfMap = map[string]string{
		// openssl 1.0.2*
		Linuxdefaulefilename102: "openssl_1_0_2a_kern.o",

		// openssl 1.1.0*
		Linuxdefaulefilename110: "openssl_1_1_0a_kern.o",

		// openssl 1.1.1*
		Linuxdefaulefilename111: "openssl_1_1_1j_kern.o",

		// openssl 3.0.* and openssl 3.1.*
		Linuxdefaulefilename30: "openssl_3_0_0_kern.o",

		// openssl 3.2.*
		Linuxdefaulefilename320: "openssl_3_2_0_kern.o",

		// boringssl
		// git repo: https://android.googlesource.com/platform/external/boringssl/+/refs/heads/android12-release
		"boringssl 1.1.1":      "boringssl_a_13_kern.o",
		"boringssl_a_13":       "boringssl_a_13_kern.o",
		"boringssl_a_14":       "boringssl_a_14_kern.o",
		AndroidDefauleFilename: "boringssl_a_13_kern.o",

		// non-Android boringssl
		// "boringssl na" is a special version for non-android
		// git repo: https://github.com/google/boringssl
		"boringssl na": "boringssl_na_kern.o",
	}

	// in openssl source files, there are 4 offset groups for all 1.1.1* version.
	// group a : 1.1.1a
	m.sslVersionBpfMap["openssl 1.1.1a"] = "openssl_1_1_1a_kern.o"

	// group b : 1.1.1b-1.1.1c
	m.sslVersionBpfMap["openssl 1.1.1b"] = "openssl_1_1_1b_kern.o"
	m.sslVersionBpfMap["openssl 1.1.1c"] = "openssl_1_1_1b_kern.o"

	// group c : 1.1.1d-1.1.1i
	for ch := 'd'; ch <= 'i'; ch++ {
		m.sslVersionBpfMap["openssl 1.1.1"+string(ch)] = "openssl_1_1_1d_kern.o"
	}

	// group e : 1.1.1j-1.1.1s
	for ch := 'j'; ch <= MaxSupportedOpenSSL111Version; ch++ {
		m.sslVersionBpfMap["openssl 1.1.1"+string(ch)] = "openssl_1_1_1j_kern.o"
	}

	// openssl 3.0.0 - 3.0.15
	for ch := 0; ch <= MaxSupportedOpenSSL30Version; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.0.%d", ch)] = "openssl_3_0_0_kern.o"
	}

	// openssl 3.1.0 - 3.1.4
	for ch := 0; ch <= MaxSupportedOpenSSL31Version; ch++ {
		// The OpenSSL 3.0 series is the same as the 3.1 series of offsets
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.1.%d", ch)] = "openssl_3_1_0_kern.o"
	}

	// openssl 3.2.0
	for ch := 0; ch <= SupportedOpenSSL32Version2; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = "openssl_3_2_0_kern.o"
	}

	// openssl 3.2.3 - newer
	for ch := 3; ch <= MaxSupportedOpenSSL32Version; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = "openssl_3_2_3_kern.o"
	}

	// openssl 3.3.0 - 3.3.1
	for ch := 0; ch <= SupportedOpenSSL33Version1; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_0_kern.o"
	}

	// openssl 3.3.2
	for ch := 2; ch <= MaxSupportedOpenSSL33Version; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_2_kern.o"
	}

	// openssl 1.1.0a - 1.1.0l
	for ch := 'a'; ch <= MaxSupportedOpenSSL110Version; ch++ {
		m.sslVersionBpfMap["openssl 1.1.0"+string(ch)] = "openssl_1_1_0a_kern.o"
	}

	// openssl 1.0.2a - 1.0.2u
	for ch := 'a'; ch <= MaxSupportedOpenSSL102Version; ch++ {
		m.sslVersionBpfMap["openssl 1.0.2"+string(ch)] = "openssl_1_0_2a_kern.o"
	}

}

func (m *MOpenSSLProbe) detectOpenssl(soPath string) error {
	f, err := os.OpenFile(soPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("can not open %s, with error:%v", soPath, err)
	}
	r, e := elf.NewFile(f)
	if e != nil {
		return fmt.Errorf("parse the ELF file  %s failed, with error:%v", soPath, err)
	}

	switch r.FileHeader.Machine {
	case elf.EM_X86_64:
	case elf.EM_AARCH64:
	default:
		return fmt.Errorf("unsupported arch library ,ELF Header Machine is :%s, must be one of EM_X86_64 and EM_AARCH64", r.FileHeader.Machine.String())
	}

	s := r.Section(".rodata")
	if s == nil {
		// not found
		return fmt.Errorf("detect openssl version failed, cant read .rodata section from %s", soPath)
	}

	sectionOffset := int64(s.Offset)
	sectionSize := s.Size

	r.Close()

	_, err = f.Seek(0, 0)
	if err != nil {
		return err
	}

	ret, err := f.Seek(sectionOffset, 0)
	if ret != sectionOffset || err != nil {
		return err
	}

	versionKey := ""

	// e.g : OpenSSL 1.1.1j  16 Feb 2021
	// OpenSSL 3.2.0 23 Nov 2023
	rex, err := regexp.Compile(`(OpenSSL\s\d\.\d\.[0-9a-z]+)`)
	if err != nil {
		return nil
	}

	buf := make([]byte, 1024*1024) // 1Mb
	totalReadCount := 0
	for totalReadCount < int(sectionSize) {
		var readCount int
		readCount, err = f.Read(buf)

		if err != nil {
			m.logger.Error().Err(err).Msg("read openssl version failed")
			break
		}

		if readCount == 0 {
			break
		}

		match := rex.Find(buf)
		if match != nil {
			versionKey = string(match)
			break
		}

		// Subtracting OpenSslVersionLen from totalReadCount,
		// to cover the edge-case in which openssl version string
		// could be split into two buffers. Subtraction will,
		// makes sure that last 30 bytes of previous buffer are considered.
		totalReadCount += readCount - OpenSslVersionLen

		_, err = f.Seek(sectionOffset+int64(totalReadCount), 0)
		if err != nil {
			break
		}

		clear(buf)

	}

	_ = f.Close()
	//buf = buf[:0]

	var bpfFile string
	var found bool
	if versionKey != "" {
		versionKeyLower := strings.ToLower(versionKey)
		m.conf.(*config.OpensslConfig).SslVersion = versionKeyLower
		m.logger.Info().Str("origin versionKey", versionKey).Str("versionKeyLower", versionKeyLower).Msg("OpenSSL/BoringSSL version found")
		// find the sslVersion bpfFile from sslVersionBpfMap
		bpfFile, found = m.sslVersionBpfMap[versionKeyLower]
		if found {
			m.sslBpfFile = bpfFile
			return nil
		}
	}

	isAndroid := m.conf.(*config.OpensslConfig).IsAndroid
	androidVer := m.conf.(*config.OpensslConfig).AndroidVer
	// if not found, use default
	if isAndroid {
		// sometimes,boringssl version always was "boringssl 1.1.1" on android. but offsets are different.
		// see kern/boringssl_a_13_kern.c and kern/boringssl_a_14_kern.c
		// Perhaps we can utilize the Android Version to choose a specific version of boringssl.
		// use the corresponding bpfFile
		bpfFildAndroid := fmt.Sprintf("boringssl_a_%s", androidVer)
		bpfFile, found = m.sslVersionBpfMap[bpfFildAndroid]
		if found {
			m.sslBpfFile = bpfFile
			m.logger.Info().Str("BoringSSL Version", androidVer).Msg("OpenSSL/BoringSSL version found")
		} else {
			bpfFile, _ = m.sslVersionBpfMap[AndroidDefauleFilename]
			m.logger.Warn().Str("BoringSSL Version", AndroidDefauleFilename).Msg("OpenSSL/BoringSSL version not found, used default version")
		}
	} else {
		if strings.Contains(soPath, "libssl.so.3") {
			bpfFile, _ = m.sslVersionBpfMap[Linuxdefaulefilename30]
			m.logger.Warn().Str("OpenSSL Version", Linuxdefaulefilename30).Msg("OpenSSL/BoringSSL version not found from shared library file, used default version")
		} else {
			bpfFile, _ = m.sslVersionBpfMap[Linuxdefaulefilename111]
			m.logger.Warn().Str("OpenSSL Version", Linuxdefaulefilename111).Msg("OpenSSL/BoringSSL version not found from shared library file, used default version")
		}
	}
	m.sslBpfFile = bpfFile
	return nil
}
