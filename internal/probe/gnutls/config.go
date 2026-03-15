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

package gnutls

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// GnuTLS version constants
const (
	Version_3_6 = "3.6"
	Version_3_7 = "3.7"
	Version_3_8 = "3.8"
)

// Default library paths to search for GnuTLS
var defaultGnuTLSPaths = []string{
	"/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
	"/usr/lib64/libgnutls.so.30",
	"/usr/lib/libgnutls.so.30",
	"/usr/lib/aarch64-linux-gnu/libgnutls.so.30",
	"/lib/x86_64-linux-gnu/libgnutls.so.30",
	"/lib64/libgnutls.so.30",
	"/lib/libgnutls.so.30",
}

// Config extends BaseConfig with GnuTLS-specific configuration.
type Config struct {
	*config.BaseConfig
	GnutlsPath string `json:"gnutlspath"` // Path to libgnutls.so
	GnuVersion string `json:"gnuversion"` // Detected GnuTLS version

	// Capture mode configuration
	CaptureMode string `json:"capturemode"` // "text", "keylog", or "pcap"
	KeylogFile  string `json:"keylogfile"`  // Path to keylog file (for keylog mode)

	// Pcap mode configuration
	PcapFile   string `json:"pcapfile"`   // Path to pcap/pcapng file (for pcap mode)
	Ifname     string `json:"ifname"`     // Network interface name (for pcap mode)
	PcapFilter string `json:"pcapfilter"` // BPF filter expression (for pcap mode)
}

// NewConfig creates a new GnuTLS probe configuration.
func NewConfig() *Config {
	return &Config{
		BaseConfig:  config.NewBaseConfig(),
		CaptureMode: handlers.ModeText, // Default to text mode
	}
}

// IsSupportedVersion checks if the detected GnuTLS version is supported.
func (c *Config) IsSupportedVersion() bool {
	if c.GnuVersion == "" {
		return false
	}

	// Check if version starts with supported major.minor versions
	return strings.HasPrefix(c.GnuVersion, Version_3_6) ||
		strings.HasPrefix(c.GnuVersion, Version_3_7) ||
		strings.HasPrefix(c.GnuVersion, Version_3_8)
}

// GetBPFFileName returns the BPF bytecode filename for the detected GnuTLS version.
func (c *Config) GetBPFFileName() string {
	// For GnuTLS, we use version-specific BPF files
	switch {
	case strings.HasPrefix(c.GnuVersion, Version_3_6):
		return "gnutls_3_6_kern.o"
	case strings.HasPrefix(c.GnuVersion, Version_3_7):
		return "gnutls_3_7_kern.o"
	case strings.HasPrefix(c.GnuVersion, Version_3_8):
		return "gnutls_3_7_kern.o" // 3.8 uses same as 3.7
	default:
		return "gnutls_kern.o"
	}
}

// Bytes serializes the configuration to JSON.
func (c *Config) Bytes() []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return []byte{}
	}
	return b
}

// Validate validates the GnuTLS configuration.
func (c *Config) Validate() error {
	// Detect GnuTLS library
	if err := c.detectGnuTLS(); err != nil {
		return err
	}

	// Detect GnuTLS version
	if err := c.detectVersion(); err != nil {
		return err
	}

	// Validate that the detected version is supported
	if !c.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported GnuTLS version: %s (supported: 3.6.x, 3.7.x, 3.8.x)", c.GnuVersion))
	}

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return err
	}

	return nil
}

// validateCaptureMode validates the capture mode configuration.
func (c *Config) validateCaptureMode() error {
	mode := strings.ToLower(c.CaptureMode)

	switch mode {
	case handlers.ModeText, "":
		c.CaptureMode = handlers.ModeText
		return nil
	case handlers.ModeKeylog, handlers.ModeKey:
		c.CaptureMode = handlers.ModeKeylog
		if c.KeylogFile == "" {
			return fmt.Errorf("keylog mode requires KeylogFile to be set")
		}
		dir := filepath.Dir(c.KeylogFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("keylog directory does not exist: %s", dir)
		}
		return nil
	case handlers.ModePcap, handlers.ModePcapng:
		c.CaptureMode = handlers.ModePcap
		if c.PcapFile == "" {
			return fmt.Errorf("pcap mode requires PcapFile to be set")
		}
		if c.Ifname == "" {
			return fmt.Errorf("pcap mode requires Ifname (network interface) to be set")
		}
		dir := filepath.Dir(c.PcapFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("pcap directory does not exist: %s", dir)
		}

		if err := c.validateNetworkInterface(); err != nil {
			return err
		}

		if err := c.checkTCSupport(); err != nil {
			return err
		}

		return nil
	default:
		return fmt.Errorf("unsupported capture mode: %s (supported: text, keylog, pcap)", mode)
	}
}

// detectGnuTLS locates the GnuTLS library.
func (c *Config) detectGnuTLS() error {
	if c.GnutlsPath != "" {
		if _, err := os.Stat(c.GnutlsPath); err != nil {
			return fmt.Errorf("gnutls path not found: %w", err)
		}
		return nil
	}

	for _, path := range defaultGnuTLSPaths {
		if _, err := os.Stat(path); err == nil {
			c.GnutlsPath = path
			return nil
		}
	}

	return errors.New(errors.ErrCodeConfiguration,
		"GnuTLS library not found in default paths")
}

// detectVersion detects the GnuTLS version from the library.
func (c *Config) detectVersion() error {
	version, err := readGnuTLSVersion(c.GnutlsPath)
	if err != nil {
		return fmt.Errorf("failed to detect GnuTLS version: %w", err)
	}

	c.GnuVersion = version
	return nil
}

// readGnuTLSVersion reads GnuTLS version from the library's .rodata section.
func readGnuTLSVersion(binaryPath string) (string, error) {
	f, err := os.OpenFile(binaryPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("cannot open %s: %w", binaryPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	r, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("parse ELF file %s failed: %w", binaryPath, err)
	}
	defer func() {
		_ = r.Close()
	}()

	switch r.FileHeader.Machine {
	case elf.EM_X86_64, elf.EM_AARCH64:
	default:
		return "", fmt.Errorf("unsupported architecture: %s", r.FileHeader.Machine.String())
	}

	s := r.Section(".rodata")
	if s == nil {
		return "", fmt.Errorf("cannot find .rodata section in %s", binaryPath)
	}

	sectionOffset := int64(s.Offset)
	sectionSize := s.Size

	_, err = f.Seek(sectionOffset, 0)
	if err != nil {
		return "", err
	}

	rex, err := regexp.Compile(`Enabled GnuTLS ([0-9\.]+) logging`)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024*1024)
	totalRead := 0

	for totalRead < int(sectionSize) {
		readCount, err := f.Read(buf)
		if err != nil || readCount == 0 {
			break
		}

		match := rex.FindSubmatch(buf[:readCount])
		if len(match) == 2 {
			return string(match[1]), nil
		}

		totalRead += readCount - 32
		if _, err = f.Seek(sectionOffset+int64(totalRead), 0); err != nil {
			break
		}
	}

	return "", fmt.Errorf("GnuTLS version string not found in %s", binaryPath)
}

// validateNetworkInterface checks if the specified network interface exists.
func (c *Config) validateNetworkInterface() error {
	if c.Ifname == "" {
		return nil
	}

	iface, err := net.InterfaceByName(c.Ifname)
	if err != nil {
		return fmt.Errorf("network interface '%s' not found: %w", c.Ifname, err)
	}

	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("network interface '%s' is not up", c.Ifname)
	}

	return nil
}

// checkTCSupport checks if the system supports TC (Traffic Control) classifier.
func (c *Config) checkTCSupport() error {
	if _, err := os.Stat("/proc/sys/net/core"); os.IsNotExist(err) {
		return fmt.Errorf("system networking support not available: /proc/sys/net/core not found")
	}

	if _, err := os.Stat("/sys/class/net"); os.IsNotExist(err) {
		return fmt.Errorf("network device management not available: /sys/class/net not found")
	}

	ifacePath := filepath.Join("/sys/class/net", c.Ifname)
	if _, err := os.Stat(ifacePath); os.IsNotExist(err) {
		return fmt.Errorf("network interface '%s' not found in sysfs", c.Ifname)
	}

	return nil
}
