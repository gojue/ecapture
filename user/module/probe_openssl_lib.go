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
	"ecapture/user/config"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	LinuxDefauleFilename_1_0_2 = "linux_default_1_0_2"
	LinuxDefauleFilename_1_1_0 = "linux_default_1_1_0"
	LinuxDefauleFilename_1_1_1 = "linux_default_1_1_1"
	LinuxDefauleFilename_3_0   = "linux_default_3_0"
	AndroidDefauleFilename     = "android_default"
)

const (
	MaxSupportedOpenSSL102Version = 'u'
	MaxSupportedOpenSSL110Version = 'l'
	MaxSupportedOpenSSL111Version = 'u'
	MaxSupportedOpenSSL30Version  = '9'
)

// initOpensslOffset initial BpfMap
func (m *MOpenSSLProbe) initOpensslOffset() {
	m.sslVersionBpfMap = map[string]string{
		// openssl 1.0.2*
		LinuxDefauleFilename_1_0_2: "openssl_1_0_2a_kern.o",

		// openssl 1.1.0*
		LinuxDefauleFilename_1_1_0: "openssl_1_1_0a_kern.o",

		// openssl 1.1.1*
		LinuxDefauleFilename_1_1_1: "openssl_1_1_1j_kern.o",

		// openssl 3.0.*
		LinuxDefauleFilename_3_0: "openssl_3_0_0_kern.o",

		// boringssl
		"boringssl 1.1.1":      "boringssl_a_13_kern.o",
		"boringssl_a_13":       "boringssl_a_13_kern.o",
		"boringssl_a_14":       "boringssl_a_14_kern.o",
		AndroidDefauleFilename: "boringssl_a_13_kern.o",
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

	// openssl 3.0.0 - 3.0.7
	for ch := '0'; ch <= MaxSupportedOpenSSL30Version; ch++ {
		m.sslVersionBpfMap["openssl 3.0."+string(ch)] = "openssl_3_0_0_kern.o"
	}

	// openssl 1.1.0a - 1.1.0l
	for ch := 'a'; ch <= MaxSupportedOpenSSL110Version; ch++ {
		m.sslVersionBpfMap["openssl 1.1.0"+string(ch)] = "openssl_1_1_1a_kern.o"
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
		return nil
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
	rex, err := regexp.Compile(`(OpenSSL\s\d\.\d\.[0-9a-z]+)`)
	if err != nil {
		return nil
	}

	buf := make([]byte, 1024*1024) // 1Mb
	totalReadCount := 0
	for totalReadCount < int(sectionSize) {
		readCount, err := f.Read(buf)

		if err != nil {
			m.logger.Printf("%s\t[f.Read] Error:%v\t", m.Name(), err)
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

		totalReadCount += readCount

		_, err = f.Seek(sectionOffset+int64(totalReadCount), 0)
		if err != nil {
			break
		}

		clear(buf)

	}

	f.Close()
	buf = nil

	var bpfFile string
	var found bool
	if versionKey != "" {
		versionKeyLower := strings.ToLower(versionKey)
		m.logger.Printf("%s\torigin version:%s, as key:%s", m.Name(), versionKey, versionKeyLower)
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
			m.logger.Printf("%s\tOpenSSL/BoringSSL version found, ro.build.version.release=%s\n", m.Name(), androidVer)
		} else {
			bpfFile, _ = m.sslVersionBpfMap[AndroidDefauleFilename]
			m.logger.Printf("%s\tOpenSSL/BoringSSL version not found, used default version :%s\n", m.Name(), AndroidDefauleFilename)
		}
	} else {
		if strings.Contains(soPath, "libssl.so.3") {
			bpfFile, _ = m.sslVersionBpfMap[LinuxDefauleFilename_3_0]
			m.logger.Printf("%s\tOpenSSL/BoringSSL version not found from shared library file, used default version:%s\n", m.Name(), LinuxDefauleFilename_3_0)
		} else {
			bpfFile, _ = m.sslVersionBpfMap[LinuxDefauleFilename_1_1_1]
			m.logger.Printf("%s\tOpenSSL/BoringSSL version not found from shared library file, used default version:%s\n", m.Name(), LinuxDefauleFilename_1_1_1)
		}
	}
	m.sslBpfFile = bpfFile
	return nil
}
