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
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	// Supported OpenSSL versions (simplified for Phase 4 Plan B)
	Version_1_1_1 = "1.1.1"
	Version_3_0   = "3.0"
	Version_3_1   = "3.1"

	// Default library search paths
	defaultLibSSLPath = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
)

// Config extends BaseConfig with OpenSSL-specific configuration.
type Config struct {
	*config.BaseConfig
	OpensslPath string `json:"opensslpath"` // Path to libssl.so
	SslVersion  string `json:"sslversion"`  // Detected OpenSSL version
	IsBoringSSL bool   `json:"isboringssl"` // Whether this is BoringSSL
	
	// Capture mode configuration
	CaptureMode string `json:"capturemode"` // "text", "keylog", or "pcap"
	KeylogFile  string `json:"keylogfile"`  // Path to keylog file (for keylog mode)
	
	// TODO: Add Pcap mode fields in future PRs
	// PcapFile   string `json:"pcapfile"`
	// Ifname     string `json:"ifname"`
}

// NewConfig creates a new OpenSSL probe configuration.
func NewConfig() *Config {
	return &Config{
		BaseConfig:  config.NewBaseConfig(),
		CaptureMode: "text", // Default to text mode
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("openssl config validation failed", err)
	}

	// Detect OpenSSL library
	if err := c.detectOpenSSL(); err != nil {
		return errors.NewConfigurationError("openssl detection failed", err)
	}

	// Detect version
	if err := c.detectVersion(); err != nil {
		return errors.NewConfigurationError("openssl version detection failed", err)
	}

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return errors.NewConfigurationError("capture mode validation failed", err)
	}

	return nil
}

// validateCaptureMode checks if the capture mode configuration is valid.
func (c *Config) validateCaptureMode() error {
	// Normalize capture mode
	mode := strings.ToLower(c.CaptureMode)
	c.CaptureMode = mode

	switch mode {
	case "text", "":
		// Text mode is the default, no additional validation needed
		c.CaptureMode = "text"
		return nil
	case "keylog", "key":
		// Keylog mode requires a keylog file path
		c.CaptureMode = "keylog"
		if c.KeylogFile == "" {
			return fmt.Errorf("keylog mode requires KeylogFile to be set")
		}
		// Check if we can create/write to the keylog file
		dir := filepath.Dir(c.KeylogFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("keylog directory does not exist: %s", dir)
		}
		return nil
	case "pcap", "pcapng":
		// TODO: Implement in future PR
		return fmt.Errorf("pcap mode not yet implemented (TODO: PR #3)")
	default:
		return fmt.Errorf("unsupported capture mode: %s (supported: text, keylog)", mode)
	}
}

// detectOpenSSL locates the OpenSSL library.
func (c *Config) detectOpenSSL() error {
	// If OpenSSL path is configured, validate it
	if c.OpensslPath != "" {
		if _, err := os.Stat(c.OpensslPath); err != nil {
			return fmt.Errorf("openssl path not found: %w", err)
		}
		return nil
	}

	// Try common library paths
	commonPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
		"/usr/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/aarch64-linux-gnu/libssl.so.1.1",
		"/lib/aarch64-linux-gnu/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib/libssl.so.1.1",
		"/usr/lib/libssl.so.3",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			c.OpensslPath = path
			return nil
		}
	}

	// Try to find libssl.so via ldconfig or locate
	// This is a simplified detection - production code might need more robust detection
	return fmt.Errorf("cannot find libssl.so in common paths")
}

// detectVersion determines the OpenSSL version.
func (c *Config) detectVersion() error {
	if c.OpensslPath == "" {
		return fmt.Errorf("openssl path not set")
	}

	// Check if it's BoringSSL
	if strings.Contains(c.OpensslPath, "boringssl") {
		c.IsBoringSSL = true
		c.SslVersion = Version_1_1_1 // BoringSSL is similar to 1.1.1
		return nil
	}

	// Extract version from library path or symbols
	// Simplified version detection based on path
	if strings.Contains(c.OpensslPath, "libssl.so.1.1") {
		c.SslVersion = Version_1_1_1
		return nil
	}
	if strings.Contains(c.OpensslPath, "libssl.so.3") {
		// Could be 3.0, 3.1, or 3.2+
		// For now, detect between 3.0 and 3.1 by checking symbols
		if err := c.detectVersion3x(); err != nil {
			// Fallback to 3.0
			c.SslVersion = Version_3_0
		}
		return nil
	}

	// Try to detect version from ELF symbols
	file, err := elf.Open(c.OpensslPath)
	if err != nil {
		return fmt.Errorf("failed to open openssl binary: %w", err)
	}
	defer file.Close()

	// Check for version-specific symbols
	symbols, err := file.DynamicSymbols()
	if err != nil {
		// If we can't read symbols, make a best guess based on path
		c.SslVersion = Version_1_1_1
		return nil
	}

	// Look for version-specific symbols
	// OpenSSL 3.0+ has different symbol patterns
	hasProviders := false
	for _, sym := range symbols {
		if strings.Contains(sym.Name, "OSSL_PROVIDER") {
			hasProviders = true
			break
		}
	}

	if hasProviders {
		c.SslVersion = Version_3_0
	} else {
		c.SslVersion = Version_1_1_1
	}

	return nil
}

// detectVersion3x attempts to distinguish between OpenSSL 3.0 and 3.1
func (c *Config) detectVersion3x() error {
	// Read the actual shared library to check version string
	// This is a simplified approach - production code might parse
	// the version info more carefully

	// Try to resolve the actual file (follow symlinks)
	realPath, err := filepath.EvalSymlinks(c.OpensslPath)
	if err != nil {
		return err
	}

	// Check if filename contains version info
	base := filepath.Base(realPath)
	if strings.Contains(base, "3.1") {
		c.SslVersion = Version_3_1
		return nil
	}
	if strings.Contains(base, "3.0") {
		c.SslVersion = Version_3_0
		return nil
	}

	// Default to 3.0 for OpenSSL 3.x
	c.SslVersion = Version_3_0
	return nil
}

// IsSupportedVersion checks if the detected version is supported.
func (c *Config) IsSupportedVersion() bool {
	switch c.SslVersion {
	case Version_1_1_1, Version_3_0, Version_3_1:
		return true
	default:
		return false
	}
}

// GetBPFFileName returns the eBPF object file name for the detected version.
func (c *Config) GetBPFFileName() string {
	// Simplified for Phase 4 Plan B - return generic file
	// TODO: Support version-specific eBPF files in future PRs
	if c.IsBoringSSL {
		return "openssl_kern_boringssl.o"
	}

	switch c.SslVersion {
	case Version_1_1_1:
		return "openssl_1_1_1_kern.o"
	case Version_3_0:
		return "openssl_3_0_0_kern.o"
	case Version_3_1:
		return "openssl_3_0_0_kern.o" // 3.1 uses same as 3.0
	default:
		return "openssl_kern.o"
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
