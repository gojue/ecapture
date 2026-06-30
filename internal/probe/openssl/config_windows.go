//go:build windows
// +build windows

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

package openssl

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

const (
	// Windows-specific constants
	DefaultSchannelPath = "C:\\Windows\\System32\\schannel.dll"
	DefaultSSPIPath     = "C:\\Windows\\System32\\secur32.dll"
)

// Config extends BaseConfig with OpenSSL/Schannel-specific configuration for Windows.
type Config struct {
	*config.BaseConfig
	OpensslPath string `json:"opensslpath"` // Path to Schannel/secur32 DLL

	// Capture mode configuration
	CaptureMode string `json:"capturemode"` // "text", "keylog", or "pcap"
	KeylogFile  string `json:"keylogfile"`  // Path to keylog file
	PcapFile    string `json:"pcapfile"`    // Path to pcap file
	Ifname      string `json:"ifname"`      // Network interface name
	PcapFilter  string `json:"pcapfilter"`  // BPF filter expression

	// Detection results
	SslVersion      string   `json:"sslversion"`
	IsBoringSSL     bool     `json:"isboringssl"`
	MasterHookFuncs []string `json:"masterhookfuncs"`
	SslBpfFile      string   `json:"sslbpffile"`
	IsAndroid       bool     `json:"is_android"`
	AndroidVer      string   `json:"androidver"`

	// Windows-specific fields
	UseSchannel bool     `json:"use_schannel"` // Whether to use Schannel ETW provider
	HookOpenSSL bool     `json:"hook_openssl"` // Whether to hook OpenSSL DLL on Windows
	OpenSSLDll  string   `json:"openssl_dll"`  // Path to OpenSSL DLL on Windows (libssl-3-x64.dll etc.)
	HookTargets []string `json:"hook_targets"` // List of DLLs to hook for TLS capture
}

// NewConfig creates a new OpenSSL probe configuration for Windows.
func NewConfig() *Config {
	return &Config{
		BaseConfig:  config.NewBaseConfig(),
		CaptureMode: "text",
		UseSchannel: true, // Default to Schannel ETW on Windows
	}
}

// Validate checks if the configuration is valid on Windows.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("openssl config validation failed", err)
	}

	// Detect TLS libraries on Windows
	if err := c.detectOpenSSL(); err != nil {
		return errors.NewConfigurationError("TLS library detection failed", err)
	}

	if err := c.detectOS(); err != nil {
		return errors.NewConfigurationError("OS detection failed", err)
	}

	if err := c.validateConfig(); err != nil {
		return errors.NewConfigurationError("config validation failed", err)
	}

	c.setDefaultIfname()

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return errors.NewConfigurationError("capture mode validation failed", err)
	}

	return nil
}

// detectOpenSSL detects TLS libraries on Windows.
// On Windows, we look for:
// 1. Schannel (built-in Windows TLS) - always available
// 2. OpenSSL DLLs (libssl-3-x64.dll, libssl-1_1-x64.dll, etc.)
// 3. LibreSSL DLLs
func (c *Config) detectOpenSSL() error {
	c.UseSchannel = true // Schannel is always available on Windows
	c.HookTargets = make([]string, 0)

	// If a specific OpenSSL DLL is configured, validate it
	if c.OpensslPath != "" {
		if _, err := os.Stat(c.OpensslPath); err != nil {
			return errors.Wrap(errors.ErrCodeConfiguration, "configured TLS library not found", err).
				WithContext("path", c.OpensslPath)
		}
		c.HookOpenSSL = true
		c.OpenSSLDll = c.OpensslPath
		c.HookTargets = append(c.HookTargets, c.OpensslPath)
		return nil
	}

	// Auto-detect OpenSSL DLLs in common Windows paths
	commonPaths := []string{
		// OpenSSL 3.x
		`C:\Program Files\OpenSSL-Win64\bin\libssl-3-x64.dll`,
		`C:\Program Files\OpenSSL\bin\libssl-3-x64.dll`,
		`C:\Program Files (x86)\OpenSSL-Win32\bin\libssl-3.dll`,
		// OpenSSL 1.1.x
		`C:\Program Files\OpenSSL-Win64\bin\libssl-1_1-x64.dll`,
		`C:\Program Files\OpenSSL\bin\libssl-1_1-x64.dll`,
		`C:\Program Files (x86)\OpenSSL-Win32\bin\libssl-1_1.dll`,
		// Common application-bundled OpenSSL
		`C:\Windows\System32\libssl-3-x64.dll`,
		`C:\Windows\System32\libssl-1_1-x64.dll`,
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			c.HookOpenSSL = true
			c.OpenSSLDll = path
			c.OpensslPath = path
			c.HookTargets = append(c.HookTargets, path)
			return nil
		}
	}

	// Fall back to Schannel-only mode
	c.UseSchannel = true
	c.OpensslPath = DefaultSchannelPath
	return nil
}

// detectOS detects OS-specific TLS settings on Windows.
func (c *Config) detectOS() error {
	c.IsAndroid = false
	c.IsBoringSSL = false

	if c.HookOpenSSL && c.OpenSSLDll != "" {
		// Detect OpenSSL version from DLL
		c.SslVersion = c.detectWindowsOpenSSLVersion()
	}

	if c.UseSchannel {
		c.SslVersion = "schannel"
		c.MasterHookFuncs = []string{"EncryptMessage", "DecryptMessage"}
	}

	return nil
}

// detectWindowsOpenSSLVersion detects the OpenSSL version from a Windows DLL.
func (c *Config) detectWindowsOpenSSLVersion() string {
	// On Windows, we can read the version from the DLL's version info resource
	// or from the .rdata section. Simplified for initial implementation.
	dllPath := c.OpenSSLDll

	// Try to read version from file version info
	data, err := os.ReadFile(dllPath)
	if err != nil {
		return "unknown"
	}

	// Simple search for version string in binary
	versionPatterns := []string{
		"OpenSSL 3.5",
		"OpenSSL 3.4",
		"OpenSSL 3.3",
		"OpenSSL 3.2",
		"OpenSSL 3.1",
		"OpenSSL 3.0",
		"OpenSSL 1.1.1",
		"OpenSSL 1.1.0",
	}

	for _, pattern := range versionPatterns {
		if strings.Contains(string(data), pattern) {
			return strings.ToLower(pattern)
		}
	}

	return "unknown"
}

// setDefaultIfname sets the default network interface name on Windows.
func (c *Config) setDefaultIfname() {
	if c.Ifname != "" {
		return
	}

	// On Windows, try to find the primary network adapter
	interfaces, err := net.Interfaces()
	if err != nil {
		c.Ifname = "Ethernet"
		return
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err == nil && len(addrs) > 0 {
				c.Ifname = iface.Name
				return
			}
		}
	}

	c.Ifname = "Ethernet"
}

func (c *Config) validateConfig() error {
	if !c.UseSchannel && !c.HookOpenSSL {
		return errors.New(errors.ErrCodeConfiguration, "no TLS library found: neither Schannel nor OpenSSL detected")
	}
	return nil
}

// validateCaptureMode checks if the capture mode configuration is valid.
func (c *Config) validateCaptureMode() error {
	mode := strings.ToLower(c.CaptureMode)
	c.CaptureMode = mode

	switch mode {
	case "text", "":
		c.CaptureMode = "text"
		return nil
	case handlers.ModeKeylog, handlers.ModeKey:
		c.CaptureMode = handlers.ModeKeylog
		if c.KeylogFile == "" {
			return errors.New(errors.ErrCodeConfiguration, "keylog mode requires KeylogFile to be set")
		}
		dir := filepath.Dir(c.KeylogFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return errors.Wrap(errors.ErrCodeConfiguration, "keylog directory does not exist", err).
				WithContext("directory", dir)
		}
		return nil
	case handlers.ModePcap, handlers.ModePcapng:
		c.CaptureMode = handlers.ModePcap
		if c.PcapFile == "" {
			return errors.New(errors.ErrCodeConfiguration, "pcap mode requires PcapFile to be set")
		}
		if c.Ifname == "" {
			return errors.New(errors.ErrCodeConfiguration, "pcap mode requires Ifname (network interface) to be set")
		}
		dir := filepath.Dir(c.PcapFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return errors.Wrap(errors.ErrCodeConfiguration, "pcap directory does not exist", err).
				WithContext("directory", dir)
		}
		return nil
	default:
		return errors.New(errors.ErrCodeConfiguration, "unsupported capture mode").
			WithContext("mode", mode).
			WithContext("supported", "text, keylog, pcap")
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

// GetKeylogFile returns the keylog file path.
func (c *Config) GetKeylogFile() string {
	return c.KeylogFile
}
