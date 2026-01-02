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

package gotls

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config holds the configuration for GoTLS probe
type Config struct {
	// CaptureMode specifies the output mode: "text", "keylog", or "pcap"
	CaptureMode string

	// KeylogFile is the path to write TLS keylog output (for keylog mode)
	KeylogFile string

	// PcapFile is the path to write pcap output (for pcap mode)
	PcapFile string

	// Ifname is the network interface name for packet capture (for pcap mode)
	Ifname string

	// PcapFilter is an optional BPF filter expression (for pcap mode)
	PcapFilter string

	// GoVersion is the detected Go runtime version
	GoVersion string

	// Pid is the target process ID (0 means capture all processes)
	Pid uint32
}

// NewConfig creates a new GoTLS config with default values
func NewConfig() *Config {
	return &Config{
		CaptureMode: "text",
		GoVersion:   "",
		Pid:         0,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Detect Go version
	if c.GoVersion == "" {
		version := detectGoVersion()
		if version == "" {
			return fmt.Errorf("failed to detect Go version")
		}
		c.GoVersion = version
	}

	// Validate Go version (require Go 1.17+)
	if !isGoVersionSupported(c.GoVersion) {
		return fmt.Errorf("unsupported Go version: %s (require Go 1.17+)", c.GoVersion)
	}

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return err
	}

	return nil
}

// validateCaptureMode validates the capture mode and related configurations
func (c *Config) validateCaptureMode() error {
	switch c.CaptureMode {
	case "text":
		// Text mode has no additional requirements
		return nil

	case "keylog":
		// Keylog mode requires KeylogFile
		if c.KeylogFile == "" {
			return fmt.Errorf("keylog mode requires KeylogFile to be set")
		}

		// Check if directory exists and is writable
		dir := filepath.Dir(c.KeylogFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("keylog directory does not exist: %s", dir)
		}

		// Check if directory is writable
		testFile := filepath.Join(dir, ".write_test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			return fmt.Errorf("keylog directory is not writable: %s", dir)
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

		// Check if directory exists and is writable
		dir := filepath.Dir(c.PcapFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("pcap directory does not exist: %s", dir)
		}

		// Check if directory is writable
		testFile := filepath.Join(dir, ".write_test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			return fmt.Errorf("pcap directory is not writable: %s", dir)
		}
		os.Remove(testFile)

		// Validate network interface
		if err := c.validateNetworkInterface(); err != nil {
			return err
		}

		// Check TC support
		if err := c.checkTCSupport(); err != nil {
			return err
		}

		return nil

	default:
		return fmt.Errorf("invalid capture mode: %s (must be 'text', 'keylog', or 'pcap')", c.CaptureMode)
	}
}

// validateNetworkInterface validates that the network interface exists and is UP
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

// checkTCSupport checks if the system supports TC (Traffic Control) classifier
func (c *Config) checkTCSupport() error {
	// Check if /proc/sys/net/core exists (basic networking support)
	if _, err := os.Stat("/proc/sys/net/core"); os.IsNotExist(err) {
		return fmt.Errorf("system networking support not available: /proc/sys/net/core not found")
	}

	// Check if /sys/class/net exists (network device management)
	if _, err := os.Stat("/sys/class/net"); os.IsNotExist(err) {
		return fmt.Errorf("network device management not available: /sys/class/net not found")
	}

	// Check if interface exists in sysfs
	ifacePath := filepath.Join("/sys/class/net", c.Ifname)
	if _, err := os.Stat(ifacePath); os.IsNotExist(err) {
		return fmt.Errorf("network interface '%s' not found in sysfs", c.Ifname)
	}

	// Note: Full TC qdisc clsact and eBPF program validation will be done
	// during probe initialization when we actually attach the eBPF program

	return nil
}

// GetBPFFileName returns the eBPF object file name for the detected Go version
func (c *Config) GetBPFFileName() string {
	// For now, use a generic gotls probe
	// In future, we may need version-specific eBPF programs
	return "gotls_kern.o"
}

// detectGoVersion detects the Go runtime version
func detectGoVersion() string {
	// Get Go version from runtime
	version := runtime.Version()
	// version is like "go1.21.0" or "go1.20.1"
	return version
}

// isGoVersionSupported checks if the Go version is supported
// We support Go 1.17+ as crypto/tls major changes happened in 1.17
func isGoVersionSupported(version string) bool {
	// Remove "go" prefix
	version = strings.TrimPrefix(version, "go")

	// Parse major.minor version
	var major, minor int
	_, err := fmt.Sscanf(version, "%d.%d", &major, &minor)
	if err != nil {
		return false
	}

	// Check if Go 1.17 or later
	if major > 1 {
		return true
	}
	if major == 1 && minor >= 17 {
		return true
	}

	return false
}
