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

package nspr

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

// Config holds the configuration for NSPR/NSS probe
type Config struct {
	*config.BaseConfig

	// NSSPath is the path to the NSS library (libnss3.so)
	NSSPath string `json:"nss_path"`

	// NSPRPath is the path to the NSPR library (libnspr4.so)
	NSPRPath string `json:"nspr_path"`
}

// NewConfig creates a new NSPR config with default values
func NewConfig() *Config {
	return &Config{
		BaseConfig: config.NewBaseConfig(),
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Chain base validation first
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("nspr base config validation failed", err)
	}

	// Detect NSS library if not provided
	if c.NSSPath == "" {
		path, err := c.findNSSLibrary()
		if err != nil {
			return errors.NewConfigurationError("NSS library not found", err)
		}
		c.NSSPath = path
	}

	// Validate NSS library exists
	if _, err := os.Stat(c.NSSPath); os.IsNotExist(err) {
		return errors.NewConfigurationError(fmt.Sprintf("NSS library not found: %s", c.NSSPath), nil)
	}

	// Detect NSPR library if not provided
	if c.NSPRPath == "" {
		path, err := c.findNSPRLibrary()
		if err != nil {
			return errors.NewConfigurationError("NSPR library not found", err)
		}
		c.NSPRPath = path
	}

	// Validate NSPR library exists
	if _, err := os.Stat(c.NSPRPath); os.IsNotExist(err) {
		return errors.NewConfigurationError(fmt.Sprintf("NSPR library not found: %s", c.NSPRPath), nil)
	}

	// Warn if NSPR functions are found in libnss3.so instead of libnspr4.so
	// In normal circumstances, PR_Write/PR_Read should be in libnspr4.so
	// For more information, see: https://github.com/gojue/ecapture/issues/662
	if strings.Contains(c.NSPRPath, "libnss3.so") || strings.Contains(c.NSPRPath, "libnss.so") {
		// This is acceptable but may require explicit --nspr path specification
	}

	// Detect and validate NSS version
	version, err := c.readNSSVersion(c.NSSPath)
	if err != nil {
		return errors.NewConfigurationError("failed to read NSS version", err)
	}

	if !c.isSupportedVersion(version) {
		return errors.NewConfigurationError(fmt.Sprintf("unsupported NSS version: %s (supported: 3.x)", version), nil)
	}

	return nil
}

// findNSSLibrary searches for NSS library in common locations
func (c *Config) findNSSLibrary() (string, error) {
	searchPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libnss3.so",
		"/usr/lib64/libnss3.so",
		"/usr/lib/libnss3.so",
		"/lib/x86_64-linux-gnu/libnss3.so",
		"/lib64/libnss3.so",
		"/lib/libnss3.so",
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("NSS library not found in standard locations")
}

// findNSPRLibrary searches for NSPR library in common locations
func (c *Config) findNSPRLibrary() (string, error) {
	searchPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libnspr4.so",
		"/usr/lib64/libnspr4.so",
		"/usr/lib/libnspr4.so",
		"/lib/x86_64-linux-gnu/libnspr4.so",
		"/lib64/libnspr4.so",
		"/lib/libnspr4.so",
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("NSPR library not found in standard locations")
}

// readNSSVersion reads the NSS version from the library
func (c *Config) readNSSVersion(binaryPath string) (string, error) {
	// Open ELF file
	file, err := elf.Open(binaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	// Read .rodata section
	section := file.Section(".rodata")
	if section == nil {
		return "", fmt.Errorf(".rodata section not found")
	}

	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read .rodata section: %w", err)
	}

	// Search for NSS version pattern: "NSS X.Y.Z" or "Network Security Services X.Y.Z"
	versionPattern := regexp.MustCompile(`NSS[ _]?(\d+\.\d+(?:\.\d+)?)`)
	matches := versionPattern.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return matches[1], nil
	}

	// Alternative pattern
	altPattern := regexp.MustCompile(`Network Security Services[ _]?(\d+\.\d+(?:\.\d+)?)`)
	matches = altPattern.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("NSS version not found in binary")
}

// isSupportedVersion checks if the NSS version is supported
func (c *Config) isSupportedVersion(version string) bool {
	// Support NSS 3.x versions
	return strings.HasPrefix(version, "3.")
}

// selectBPFFileName selects the appropriate BPF object file based on version
func (c *Config) selectBPFFileName(version string) string {
	// For stub implementation, return a placeholder
	// In real implementation, this would select the appropriate eBPF bytecode
	return "nspr_kern.o"
}

// Bytes serializes the configuration to JSON bytes (required by domain.Configuration interface)
func (c *Config) Bytes() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		// Fallback to simple format if marshaling fails
		return []byte(fmt.Sprintf(`{"nss_path":"%s","nspr_path":"%s","pid":%d}`,
			c.NSSPath, c.NSPRPath, c.Pid))
	}
	return data
}
