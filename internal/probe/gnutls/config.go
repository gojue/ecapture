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

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

var gnuTLSVersionAssets = map[string]string{
	"3.6.12": "gnutls_3_6_12_kern.o",
	"3.6.13": "gnutls_3_6_13_kern.o",
	"3.6.14": "gnutls_3_6_13_kern.o",
	"3.6.15": "gnutls_3_6_13_kern.o",
	"3.6.16": "gnutls_3_6_13_kern.o",
	"3.7.0":  "gnutls_3_7_0_kern.o",
	"3.7.1":  "gnutls_3_7_0_kern.o",
	"3.7.2":  "gnutls_3_7_0_kern.o",
	"3.7.3":  "gnutls_3_7_3_kern.o",
	"3.7.4":  "gnutls_3_7_3_kern.o",
	"3.7.5":  "gnutls_3_7_3_kern.o",
	"3.7.6":  "gnutls_3_7_3_kern.o",
	"3.7.7":  "gnutls_3_7_7_kern.o",
	"3.7.8":  "gnutls_3_7_7_kern.o",
	"3.7.9":  "gnutls_3_7_7_kern.o",
	"3.7.10": "gnutls_3_7_7_kern.o",
	"3.7.11": "gnutls_3_7_7_kern.o",
	"3.8.0":  "gnutls_3_7_7_kern.o",
	"3.8.1":  "gnutls_3_7_7_kern.o",
	"3.8.2":  "gnutls_3_7_7_kern.o",
	"3.8.3":  "gnutls_3_7_7_kern.o",
	"3.8.4":  "gnutls_3_8_4_kern.o",
	"3.8.5":  "gnutls_3_8_4_kern.o",
	"3.8.6":  "gnutls_3_8_4_kern.o",
	"3.8.7":  "gnutls_3_8_7_kern.o",
	"3.8.8":  "gnutls_3_8_7_kern.o",
	"3.8.9":  "gnutls_3_8_7_kern.o",
}

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
	_, ok := gnuTLSVersionAssets[c.GnuVersion]
	return ok
}

// GetBPFFileName returns the BPF bytecode filename for the detected GnuTLS version.
func (c *Config) GetBPFFileName() string {
	return gnuTLSVersionAssets[c.GnuVersion]
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
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("gnutls config validation failed", err)
	}
	// Detect GnuTLS library
	if err := c.detectGnuTLS(); err != nil {
		return err
	}

	// Preserve an explicitly configured version and avoid repeating ELF scans
	// when Validate is called by both the CLI and BaseProbe.Initialize.
	if c.GnuVersion == "" {
		if err := c.detectVersion(); err != nil {
			return err
		}
	}

	// Validate that the detected version is supported
	if !c.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported GnuTLS version: %s (supported: 3.6.12-3.6.16, 3.7.0-3.7.11, 3.8.0-3.8.9)", c.GnuVersion))
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
		addr, err := writers.NormalizeEventAddress(writers.EventFormatText, c.EventCollectorAddr, c.KeylogFile, c.PcapFile)
		if err != nil {
			return err
		}
		c.EventCollectorAddr = addr
		return writers.NewWriterFactory().ValidateEventSinkAddress(writers.EventSinkOptions{Address: addr, Format: writers.EventFormatText, RotateConfig: writers.NewRotateConfig(c.GetEventRotation())})
	case handlers.ModeKeylog, handlers.ModeKey:
		c.CaptureMode = handlers.ModeKeylog
		addr, err := writers.NormalizeEventAddress(writers.EventFormatKeylog, c.EventCollectorAddr, c.KeylogFile, c.PcapFile)
		if err != nil {
			return err
		}
		c.EventCollectorAddr = addr
		return writers.NewWriterFactory().ValidateEventSinkAddress(writers.EventSinkOptions{Address: addr, Format: writers.EventFormatKeylog, RotateConfig: writers.NewRotateConfig(c.GetEventRotation())})
	case handlers.ModePcap, handlers.ModePcapng:
		c.CaptureMode = handlers.ModePcapng
		if c.Ifname == "" {
			return fmt.Errorf("pcap mode requires Ifname (network interface) to be set")
		}
		addr, err := writers.NormalizeEventAddress(writers.EventFormatPcapng, c.EventCollectorAddr, c.KeylogFile, c.PcapFile)
		if err != nil {
			return err
		}
		c.EventCollectorAddr = addr
		if err := writers.NewWriterFactory().ValidateEventSinkAddress(writers.EventSinkOptions{Address: addr, Format: writers.EventFormatPcapng, RotateConfig: writers.NewRotateConfig(c.GetEventRotation())}); err != nil {
			return err
		}
		if err := writers.ValidateChannelSeparation(writers.EventFormatPcapng, addr, c.LoggerAddr); err != nil {
			return err
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

// GetCaptureMode returns the normalized captured-event representation.
func (c *Config) GetCaptureMode() string {
	return c.CaptureMode
}
