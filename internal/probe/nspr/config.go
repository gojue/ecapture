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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Config holds the configuration for NSPR/NSS probe
type Config struct {
	// NSSPath is the path to the NSS library (libnss3.so)
	NSSPath string

	// NSPRPath is the path to the NSPR library (libnspr4.so)
	NSPRPath string

	// CaptureMode determines the output format: "text", "keylog", or "pcap"
	CaptureMode string

	// KeylogFile is the path to write NSS Key Log Format output (keylog mode)
	KeylogFile string

	// PcapFile is the path to write PCAPNG format output (pcap mode)
	PcapFile string

	// Ifname is the network interface name for packet capture (pcap mode)
	Ifname string

	// PcapFilter is an optional BPF filter expression (pcap mode)
	PcapFilter string

	// PID is the target process ID (0 for all processes)
	PID uint32
}

// NewConfig creates a new NSPR config with default values
func NewConfig() *Config {
	return &Config{
		CaptureMode: "text",
		PID:         0,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Detect NSS library if not provided
	if c.NSSPath == "" {
		path, err := c.findNSSLibrary()
		if err != nil {
			return fmt.Errorf("NSS library not found: %w", err)
		}
		c.NSSPath = path
	}

	// Validate NSS library exists
	if _, err := os.Stat(c.NSSPath); os.IsNotExist(err) {
		return fmt.Errorf("NSS library not found: %s", c.NSSPath)
	}

	// Detect NSPR library if not provided
	if c.NSPRPath == "" {
		path, err := c.findNSPRLibrary()
		if err != nil {
			return fmt.Errorf("NSPR library not found: %w", err)
		}
		c.NSPRPath = path
	}

	// Validate NSPR library exists
	if _, err := os.Stat(c.NSPRPath); os.IsNotExist(err) {
		return fmt.Errorf("NSPR library not found: %s", c.NSPRPath)
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
		return fmt.Errorf("failed to read NSS version: %w", err)
	}

	if !c.isSupportedVersion(version) {
		return fmt.Errorf("unsupported NSS version: %s (supported: 3.x)", version)
	}

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return err
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
	defer file.Close()

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

// validateCaptureMode validates the capture mode and related configuration
func (c *Config) validateCaptureMode() error {
	switch c.CaptureMode {
	case "text":
		// Text mode requires no additional configuration
		return nil

	case "keylog":
		// Keylog mode requires KeylogFile
		if c.KeylogFile == "" {
			return fmt.Errorf("keylog mode requires KeylogFile to be set")
		}

		// Validate parent directory exists and is writable
		dir := filepath.Dir(c.KeylogFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("keylog file directory does not exist: %s", dir)
		}

		// Check if directory is writable
		testFile := filepath.Join(dir, ".write_test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			return fmt.Errorf("keylog file directory is not writable: %s", dir)
		}
		os.Remove(testFile)

		return nil

	case "pcap":
		// Pcap mode requires PcapFile and Ifname
		if c.PcapFile == "" {
			return fmt.Errorf("pcap mode requires PcapFile to be set")
		}
		if c.Ifname == "" {
			return fmt.Errorf("pcap mode requires Ifname to be set")
		}

		// Validate parent directory exists and is writable
		dir := filepath.Dir(c.PcapFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("pcap file directory does not exist: %s", dir)
		}

		// Check if directory is writable
		testFile := filepath.Join(dir, ".write_test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			return fmt.Errorf("pcap file directory is not writable: %s", dir)
		}
		os.Remove(testFile)

		// Validate network interface
		if err := c.validateNetworkInterface(); err != nil {
			return err
		}

		// Check TC support
		if err := c.checkTCSupport(); err != nil {
			return fmt.Errorf("TC classifier support check failed: %w", err)
		}

		return nil

	default:
		return fmt.Errorf("invalid capture mode: %s (must be 'text', 'keylog', or 'pcap')", c.CaptureMode)
	}
}

// validateNetworkInterface validates that the network interface exists and is up
func (c *Config) validateNetworkInterface() error {
	iface, err := net.InterfaceByName(c.Ifname)
	if err != nil {
		return fmt.Errorf("network interface '%s' not found: %w", c.Ifname, err)
	}

	// Check if interface is UP
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("network interface '%s' is not up", c.Ifname)
	}

	return nil
}

// checkTCSupport performs basic validation of TC (Traffic Control) classifier support
func (c *Config) checkTCSupport() error {
	// Check if /proc/sys/net/core exists (basic networking support)
	if _, err := os.Stat("/proc/sys/net/core"); os.IsNotExist(err) {
		return fmt.Errorf("system networking support not available: /proc/sys/net/core not found")
	}

	// Check if /sys/class/net exists (network device management)
	if _, err := os.Stat("/sys/class/net"); os.IsNotExist(err) {
		return fmt.Errorf("network device management not available: /sys/class/net not found")
	}

	// Check if the interface exists in sysfs
	ifacePath := filepath.Join("/sys/class/net", c.Ifname)
	if _, err := os.Stat(ifacePath); os.IsNotExist(err) {
		return fmt.Errorf("network interface '%s' not found in sysfs", c.Ifname)
	}

	// Note: Full TC validation (checking for clsact qdisc, eBPF TC program support, etc.)
	// should be done during probe initialization when actually attaching TC hooks.
	// This is just a basic sanity check.

	return nil
}

// GetHex returns whether to use hex encoding for output (always false for NSPR)
func (c *Config) GetHex() bool {
	return false
}

// GetPid returns the target process ID
func (c *Config) GetPid() uint64 {
	return uint64(c.PID)
}

// GetUid returns the target user ID (not used for NSPR)
func (c *Config) GetUid() uint64 {
	return 0
}

// GetDebug returns whether debug mode is enabled (not used for NSPR)
func (c *Config) GetDebug() bool {
	return false
}

// GetBTF returns the BTF mode (not used for NSPR)
func (c *Config) GetBTF() uint8 {
	return 0
}

// GetPerCpuMapSize returns the eBPF map size per CPU (not used for NSPR)
func (c *Config) GetPerCpuMapSize() int {
	return 0
}

// GetTruncateSize returns the maximum size for truncating captured data (not used for NSPR)
func (c *Config) GetTruncateSize() uint64 {
	return 0
}

// EnableGlobalVar checks if kernel supports global variables (not used for NSPR)
func (c *Config) EnableGlobalVar() bool {
	return false
}

// GetByteCodeFileMode returns the bytecode file selection mode (not used for NSPR)
func (c *Config) GetByteCodeFileMode() uint8 {
	return 0
}

// Bytes serializes the configuration to JSON bytes (required by domain.Configuration interface)
func (c *Config) Bytes() []byte {
	// Implement simple JSON-like serialization for HTTP interface compatibility
	return []byte(fmt.Sprintf(`{"nss_path":"%s","nspr_path":"%s","capture_mode":"%s","keylog_file":"%s","pcap_file":"%s","ifname":"%s","pcap_filter":"%s","pid":%d}`,
		c.NSSPath, c.NSPRPath, c.CaptureMode, c.KeylogFile, c.PcapFile, c.Ifname, c.PcapFilter, c.PID))
}
