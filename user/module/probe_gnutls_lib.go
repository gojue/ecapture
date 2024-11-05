// Author: yuweizzz <yuwei764969238@gmail.com>.
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
	"os"
	"path"
	"regexp"

	"github.com/gojue/ecapture/user/config"
)

const GnuTLSDefaultVersion = "3.6.12"
const GnuTLSVersionLen = 32

func readelf(binaryPath string) (string, error) {
	f, err := os.OpenFile(binaryPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("Can not open %s, with error: %v", binaryPath, err)
	}
	defer f.Close()
	r, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("Parse the ELF file %s failed, with error: %v", binaryPath, err)
	}
	defer r.Close()

	switch r.FileHeader.Machine {
	case elf.EM_X86_64:
	case elf.EM_AARCH64:
	default:
		return "", fmt.Errorf(
			"Unsupported arch library, ELF Header Machine is: %s, must be one of EM_X86_64 and EM_AARCH64",
			r.FileHeader.Machine.String())
	}

	s := r.Section(".rodata")
	if s == nil {
		// .rodata not found
		return "", fmt.Errorf("Detect GnuTLS version failed, cant read .rodata section from %s", binaryPath)
	}

	sectionOffset := int64(s.Offset)
	sectionSize := s.Size

	_, err = f.Seek(0, 0)
	if err != nil {
		return "", err
	}

	ret, err := f.Seek(sectionOffset, 0)
	if ret != sectionOffset || err != nil {
		return "", err
	}

	rex, err := regexp.Compile(`Enabled GnuTLS ([0-9\.]+) logging...`)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024*1024) // 1Mb
	totalReadCount := 0
	for totalReadCount < int(sectionSize) {
		readCount, err := f.Read(buf)
		if err != nil {
			return "", err
		}

		if readCount == 0 {
			break
		}

		match := rex.FindSubmatch(buf)
		if len(match) == 2 {
			return string(match[1]), nil
		}

		// just like "probe_openssl_lib.go",
		// "Enabled GnuTLS 3.x.xx logging..." is 32 chars.
		totalReadCount += readCount - GnuTLSVersionLen

		_, err = f.Seek(sectionOffset+int64(totalReadCount), 0)
		if err != nil {
			return "", err
		}
		clear(buf)
	}
	return "", fmt.Errorf("Unknown error")
}

func (m *MGnutlsProbe) detectGnutls() error {
	var binaryPath string
	switch m.conf.(*config.GnutlsConfig).ElfType {
	case config.ElfTypeSo:
		binaryPath = m.conf.(*config.GnutlsConfig).Gnutls
	default:
		// Default: "/lib/x86_64-linux-gnu/libgnutls.so.30"
		binaryPath = path.Join(defaultSoPath, "libgnutls.so.30")
	}
	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	ConfigSslVersion := m.conf.(*config.GnutlsConfig).SslVersion
	if len(ConfigSslVersion) > 0 {
		m.sslVersion = ConfigSslVersion
		m.logger.Info().Str("GnuTLS Version", m.sslVersion).Msg("GnuTLS version configured")
	} else {
		sslVersion, err := readelf(binaryPath)
		if err != nil {
			m.logger.Error().Err(err)
		}
		m.sslVersion = sslVersion
		if len(m.sslVersion) == 0 {
			m.logger.Warn().Str("GnuTLS Version", GnuTLSDefaultVersion).Msg("GnuTLS version not found, used default version")
			m.sslVersion = GnuTLSDefaultVersion
		}
		m.logger.Info().Str("Version", m.sslVersion).Msg("GnuTLS version found")
	}

	m.logger.Info().Str("binaryPath", binaryPath).Uint8("elfType", m.conf.(*config.GnutlsConfig).ElfType).Msg("GnuTLS binary path")
	switch m.sslVersion {
	case "3.8.7":
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_8_7_kern.o")
	case "3.8.6", "3.8.5", "3.8.4":
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_8_4_kern.o")
	case "3.8.3", "3.8.2", "3.8.1", "3.8.0", "3.7.11", "3.7.10", "3.7.9", "3.7.8", "3.7.7":
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_7_7_kern.o")
	case "3.7.6", "3.7.5", "3.7.4", "3.7.3":
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_7_3_kern.o")
	case "3.7.2", "3.7.1", "3.7.0":
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_7_0_kern.o")
	case "3.6.16", "3.6.15", "3.6.14":
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_6_14_kern.o")
	case "3.6.13", "3.6.12":
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_6_12_kern.o")
	default:
		m.sslBpfFile = m.geteBPFName("user/bytecode/gnutls_3_6_12_kern.o")
		m.logger.Warn().Msg("GnuTLS version not supported, used default bpf bytecode file")
	}
	m.logger.Info().Str("bytecode filename", m.sslBpfFile).Msg("BPF bytecode loaded")
	return nil
}
