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
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gojue/ecapture/user/config"
)

const (
	LinuxDefaultFilename102 = "linux_default_1_0_2"
	LinuxDefaultFilename110 = "linux_default_1_1_0"
	LinuxDefaultFilename111 = "linux_default_1_1_1"
	LinuxDefaultFilename30  = "linux_default_3_0"
	LinuxDefaultFilename31  = "linux_default_3_0"
	LinuxDefaultFilename320 = "linux_default_3_2"
	LinuxDefaultFilename330 = "linux_default_3_3"
	LinuxdDfaultFilename340 = "linux_default_3_4"
	AndroidDefaultFilename  = "android_default"

	OpenSslVersionLen = 30 // openssl version string length
)

const (
	MaxSupportedOpenSSL102Version = 'u'
	MaxSupportedOpenSSL110Version = 'l'
	MaxSupportedOpenSSL111Version = 'w'
	SupportedOpenSSL30Version12   = 12 // openssl 3.0.12
	MaxSupportedOpenSSL30Version  = 17
	MaxSupportedOpenSSL31Version  = 8
	SupportedOpenSSL32Version2    = 2 // openssl 3.2.0 ~ 3.2.2
	SupportedOpenSSL32Version3    = 3 // openssl 3.2.3
	SupportedOpenSSL32Version4    = 5 // openssl 3.2.5
	MaxSupportedOpenSSL32Version  = 3 // openssl 3.2.3 ~ newer
	SupportedOpenSSL33Version1    = 1 // openssl 3.3.0 ~ 3.3.1
	SupportedOpenSSL33Version2    = 2 // openssl 3.3.2
	MaxSupportedOpenSSL33Version  = 4 // openssl 3.3.4
	SupportedOpenSSL34Version0    = 0 // openssl 3.4.0
	MaxSupportedOpenSSL34Version  = 2 // openssl 3.4.2
	SupportedOpenSSL35Version0    = 4 // openssl 3.5.0 ~ 3.5.4
	MaxSupportedOpenSSL35Version  = 4 // openssl 3.5.4
)

var (
	ErrProbeOpensslVerNotFound         = errors.New("OpenSSL/BoringSSL version not found")
	ErrProbeOpensslVerBytecodeNotFound = errors.New("OpenSSL/BoringSSL version bytecode not found")
	OpensslNoticeVersionGuideAndroid   = "\"--ssl_version='boringssl_a_13'\" , \"--ssl_version='boringssl_a_14'\""
	OpensslNoticeVersionGuideLinux     = "\"--ssl_version='openssl x.x.x'\", support openssl 1.0.x, 1.1.x, 3.x or newer"
	OpensslNoticeUsedDefault           = "If you want to use the specific version, please set the sslVersion parameter with %s, or use \"ecapture tls --help\" for more help."
)

// initOpensslOffset initial BpfMap
func (m *MOpenSSLProbe) initOpensslOffset() {
	m.sslVersionBpfMap = map[string]string{
		// openssl 1.0.2*
		LinuxDefaultFilename102: "openssl_1_0_2a_kern.o",

		// openssl 1.1.0*
		LinuxDefaultFilename110: "openssl_1_1_0a_kern.o",

		// openssl 1.1.1*
		LinuxDefaultFilename111: "openssl_1_1_1j_kern.o",

		// openssl 3.0.* and openssl 3.1.*
		LinuxDefaultFilename30: "openssl_3_0_0_kern.o",

		// openssl 3.2.*
		LinuxDefaultFilename320: "openssl_3_2_0_kern.o",

		// boringssl
		// git repo: https://android.googlesource.com/platform/external/boringssl/+/refs/heads/android12-release
		"boringssl 1.1.1":      "boringssl_a_13_kern.o",
		"boringssl_a_13":       "boringssl_a_13_kern.o",
		"boringssl_a_14":       "boringssl_a_14_kern.o",
		"boringssl_a_15":       "boringssl_a_15_kern.o",
		AndroidDefaultFilename: "boringssl_a_13_kern.o",

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

	// support openssl 3.0.12
	// 2025-08-23  3.0.12 is a special version, the offset is different from 3.0.0 - 3.0.11, and 3.0.13 - 3.0.17, so we need to special support it
	m.sslVersionBpfMap[fmt.Sprintf("openssl 3.0.%d", SupportedOpenSSL30Version12)] = "openssl_3_0_12_kern.o"

	// openssl 3.1.0 - 3.1.8
	for ch := 0; ch <= MaxSupportedOpenSSL31Version; ch++ {
		// The OpenSSL 3.0 series is the same as the 3.1 series of offsets
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.1.%d", ch)] = "openssl_3_1_0_kern.o"
	}

	// openssl 3.2.0
	for ch := 0; ch <= SupportedOpenSSL32Version2; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = "openssl_3_2_0_kern.o"
	}

	// openssl 3.2.3
	m.sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", SupportedOpenSSL32Version3)] = "openssl_3_2_3_kern.o"
	// openssl 3.2.5
	m.sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", SupportedOpenSSL32Version4)] = "openssl_3_2_4_kern.o"

	// openssl 3.3.0 - 3.3.1
	for ch := 0; ch <= SupportedOpenSSL33Version1; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_0_kern.o"
	}

	// openssl 3.3.2
	for ch := 2; ch <= SupportedOpenSSL33Version2; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_2_kern.o"
	}

	// openssl 3.3.4
	for ch := 3; ch <= MaxSupportedOpenSSL33Version; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_3_kern.o"
	}

	// openssl 3.4.0
	for ch := 0; ch <= SupportedOpenSSL34Version0; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.4.%d", ch)] = "openssl_3_4_0_kern.o"
	}

	// openssl 3.4.1
	for ch := 1; ch <= MaxSupportedOpenSSL34Version; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.4.%d", ch)] = "openssl_3_4_1_kern.o"
	}

	// openssl 3.5.0
	for ch := 0; ch <= SupportedOpenSSL35Version0; ch++ {
		m.sslVersionBpfMap[fmt.Sprintf("openssl 3.5.%d", ch)] = "openssl_3_5_0_kern.o"
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

func (m *MOpenSSLProbe) detectOpenssl(soPath string) (string, error) {
	f, err := os.OpenFile(soPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("can not open %s, with error:%w", soPath, err)
	}
	r, e := elf.NewFile(f)
	if e != nil {
		return "", fmt.Errorf("parse the ELF file  %s failed, with error:%w", soPath, err)
	}

	switch r.FileHeader.Machine {
	case elf.EM_X86_64:
	case elf.EM_AARCH64:
	default:
		return "", fmt.Errorf("unsupported arch library ,ELF Header Machine is :%s, must be one of EM_X86_64 and EM_AARCH64", r.FileHeader.Machine.String())
	}

	s := r.Section(".rodata")
	if s == nil {
		// not found
		return "", fmt.Errorf("detect openssl version failed, cant read .rodata section from %s", soPath)
	}

	sectionOffset := int64(s.Offset)
	sectionSize := s.Size

	_ = r.Close()

	_, err = f.Seek(0, 0)
	if err != nil {
		return "", err
	}

	ret, err := f.Seek(sectionOffset, 0)
	if ret != sectionOffset || err != nil {
		return "", err
	}

	versionKey := ""

	// e.g : OpenSSL 1.1.1j  16 Feb 2021
	// OpenSSL 3.2.0 23 Nov 2023
	rex, err := regexp.Compile(`(OpenSSL\s\d\.\d\.[0-9a-z]+)`)
	if err != nil {
		return "", err
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

	if versionKey == "" {
		return "", ErrProbeOpensslVerNotFound
	}

	versionKeyLower := strings.ToLower(versionKey)

	return versionKeyLower, nil
}

func (m *MOpenSSLProbe) autoDetectBytecode(ver, soPath string, isAndroid bool) string {
	var bpfFile string
	var found bool
	// if not found, use default
	if isAndroid {
		m.conf.(*config.OpensslConfig).SslVersion = AndroidDefaultFilename
		androidVer := m.conf.(*config.OpensslConfig).AndroidVer
		if androidVer != "" {
			bpfFileKey := fmt.Sprintf("boringssl_a_%s", androidVer)
			bpfFile, found = m.sslVersionBpfMap[bpfFileKey]
			if found {
				return bpfFile
			}
		}
		bpfFile, found = m.sslVersionBpfMap[AndroidDefaultFilename]
		if !found {
			m.logger.Warn().Str("BoringSSL Version", AndroidDefaultFilename).Msg("Can not find Default BoringSSL version")
			return ""
		}
		m.logger.Warn().Msgf("OpenSSL/BoringSSL version not found, Automatically selected.%s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideAndroid))
		return bpfFile
	}

	// auto downgrade openssl version
	var isDowngrade bool
	bpfFile, isDowngrade = m.downgradeOpensslVersion(ver, soPath)
	if isDowngrade {
		m.logger.Error().Str("OpenSSL Version", ver).Str("bpfFile", bpfFile).Msgf("OpenSSL/BoringSSL version not found, used downgrade version. %s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideLinux))
	} else {
		m.logger.Error().Str("OpenSSL Version", ver).Str("bpfFile", bpfFile).Msgf("OpenSSL/BoringSSL version not found, used default version. %s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideLinux))
	}

	return bpfFile
}

func getImpNeeded(soPath string) ([]string, error) {
	var importedNeeded []string
	f, err := os.OpenFile(soPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return importedNeeded, fmt.Errorf("can not open %s, with error:%w", soPath, err)
	}

	elfFile, err := elf.NewFile(f)
	if err != nil {
		return importedNeeded, fmt.Errorf("parse the ELF file  %s failed, with error:%w", soPath, err)
	}

	// 打印外部依赖的动态链接库
	is, err := elfFile.DynString(elf.DT_NEEDED)
	//is, err := elfFile.ImportedSymbols()
	if err != nil {
		return importedNeeded, err
	}
	importedNeeded = append(importedNeeded, is...)
	return importedNeeded, nil
}

func (m *MOpenSSLProbe) downgradeOpensslVersion(ver string, soPath string) (string, bool) {
	var candidates []string
	// 未找到时，逐步截取ver查找最相近的
	for i := len(ver) - 1; i > 0; i-- {
		prefix := ver[:i]

		// 找到所有匹配前缀的key
		for libKey := range m.sslVersionBpfMap {
			if strings.HasPrefix(libKey, prefix) && isVersionLessOrEqual(libKey, ver) {
				candidates = append(candidates, libKey)
			}
		}

		if len(candidates) > 0 {
			// 按ASCII顺序排序，取最大的
			sort.Strings(candidates)
			return m.sslVersionBpfMap[candidates[len(candidates)-1]], true
		}
	}
	var bpfFile string
	if strings.Contains(soPath, "libssl.so.3") {
		m.conf.(*config.OpensslConfig).SslVersion = LinuxDefaultFilename30
		bpfFile, _ = m.sslVersionBpfMap[LinuxDefaultFilename30]
	} else {
		m.conf.(*config.OpensslConfig).SslVersion = LinuxDefaultFilename111
		bpfFile, _ = m.sslVersionBpfMap[LinuxDefaultFilename111]
	}
	return bpfFile, false
}

// isVersionLessOrEqual 比较两个版本号字符串，返回 v1 <= v2
func isVersionLessOrEqual(v1, v2 string) bool {
	// 提取版本号部分，去掉 "openssl " 前缀
	version1 := strings.TrimPrefix(v1, "openssl ")
	version2 := strings.TrimPrefix(v2, "openssl ")

	// 按点分割版本号
	parts1 := strings.Split(version1, ".")
	parts2 := strings.Split(version2, ".")

	// 比较每个部分
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1Str, p2Str string
		if i < len(parts1) {
			p1Str = parts1[i]
		} else {
			p1Str = "0"
		}
		if i < len(parts2) {
			p2Str = parts2[i]
		} else {
			p2Str = "0"
		}

		// 分别提取数字和字母部分
		num1, suffix1 := extractVersionPart(p1Str)
		num2, suffix2 := extractVersionPart(p2Str)

		// 先比较数字部分
		if num1 < num2 {
			return true
		}
		if num1 > num2 {
			return false
		}

		// 数字相等时比较字母后缀
		if suffix1 < suffix2 {
			return true
		}
		if suffix1 > suffix2 {
			return false
		}
	}

	return true // 相等时返回 true
}

// extractVersionPart 从版本号部分中提取数字和字母后缀
func extractVersionPart(s string) (int, string) {
	var numStr strings.Builder
	var suffix string

	// 提取开头的数字部分
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		numStr.WriteByte(s[i])
		i++
	}

	// 剩余部分作为后缀
	if i < len(s) {
		suffix = s[i:]
	}

	num := 0
	if numStr.Len() > 0 {
		// 忽略转换错误，因为我们已经确保了是数字
		num, _ = strconv.Atoi(numStr.String())
	}

	return num, suffix
}
