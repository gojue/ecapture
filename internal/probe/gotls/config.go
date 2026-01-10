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
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Config extends BaseConfig with GoTLS-specific configuration.
type Config struct {
	*config.BaseConfig

	// ElfPath is the path to the Go binary ELF file
	ElfPath string `json:"elf_path"`

	// CaptureMode specifies the output mode: "text", "keylog", or "pcap"
	CaptureMode string `json:"capture_mode"`

	// KeylogFile is the path to write TLS keylog output (for keylog mode)
	KeylogFile string `json:"keylog_file"`

	// PcapFile is the path to write pcap output (for pcap mode)
	PcapFile string `json:"pcap_file"`

	// Ifname is the network interface name for packet capture (for pcap mode)
	Ifname string `json:"ifname"`

	// PcapFilter is an optional BPF filter expression (for pcap mode)
	PcapFilter string `json:"pcap_filter"`

	// GoVersion is the detected Go runtime version
	GoVersion string `json:"go_version"`

	// IsRegisterABI indicates whether to use register-based ABI (Go 1.17+)
	IsRegisterABI bool `json:"is_register_abi"`

	// ReadTlsAddrs stores the offsets for Read function RET instructions (for uretprobe)
	ReadTlsAddrs []uint64 `json:"-"`

	// GoTlsWriteAddr stores the offset for Write function
	GoTlsWriteAddr uint64 `json:"-"`

	// GoTlsMasterSecretAddr stores the offset for master secret function (keylog mode)
	GoTlsMasterSecretAddr uint64 `json:"-"`
}

// NewConfig creates a new GoTLS config with default values
func NewConfig() *Config {
	return &Config{
		BaseConfig:    config.NewBaseConfig(),
		CaptureMode:   "text",
		GoVersion:     "",
		IsRegisterABI: false,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate BaseConfig first
	if err := c.BaseConfig.Validate(); err != nil {
		return fmt.Errorf("base config validation failed: %w", err)
	}

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

	// Determine ABI based on Go version
	c.IsRegisterABI = isRegisterABI(c.GoVersion)

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return err
	}

	// Find symbol addresses if ElfPath is provided
	if c.ElfPath != "" {
		if err := c.findSymbolOffsets(); err != nil {
			return fmt.Errorf("failed to find symbol offsets: %w", err)
		}
	}

	return nil
}

// validateCaptureMode validates the capture mode and related configurations
func (c *Config) validateCaptureMode() error {
	switch c.CaptureMode {
	case "text":
		// Text mode has no additional requirements
		return nil

	case handlers.ModeKeylog:
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
		_ = os.Remove(testFile)

		return nil

	case handlers.ModePcap:
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
		_ = os.Remove(testFile)

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

// isRegisterABI checks if the Go version uses register-based ABI
// Go 1.17+ uses register-based ABI, earlier versions use stack-based ABI
func isRegisterABI(version string) bool {
	// Remove "go" prefix
	version = strings.TrimPrefix(version, "go")

	// Parse major.minor version
	var major, minor int
	_, err := fmt.Sscanf(version, "%d.%d", &major, &minor)
	if err != nil {
		return false
	}

	// Go 1.17+ uses register-based ABI
	if major > 1 {
		return true
	}
	if major == 1 && minor >= 17 {
		return true
	}

	return false
}

// Bytes serializes the configuration to JSON bytes (using BaseConfig implementation)
func (c *Config) Bytes() []byte {
	// Use BaseConfig's Bytes method which handles JSON serialization properly
	return c.BaseConfig.Bytes()
}

// findSymbolOffsets finds the offsets for crypto/tls functions in the Go binary
func (c *Config) findSymbolOffsets() error {
	if c.ElfPath == "" {
		return fmt.Errorf("ElfPath is required")
	}

	// Open the ELF file
	elfFile, err := elf.Open(c.ElfPath)
	if err != nil {
		return fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer func() {
		_ = elfFile.Close()
	}()

	// Read build info to get Go version
	buildInfo, err := buildinfo.ReadFile(c.ElfPath)
	if err != nil {
		return fmt.Errorf("failed to read build info: %w", err)
	}

	// Read the Go symbol table
	symTable, err := c.readGoSymbolTable(elfFile, buildInfo.GoVersion)
	if err != nil {
		return fmt.Errorf("failed to read Go symbol table: %w", err)
	}

	// Find function symbols
	const writeFunc = "crypto/tls.(*Conn).writeRecordLocked"
	const readFunc = "crypto/tls.(*Conn).Read"
	const masterSecretFunc = "crypto/tls.(*Config).writeKeyLog"

	writeSymbol := symTable.LookupFunc(writeFunc)
	if writeSymbol == nil {
		return fmt.Errorf("write function symbol not found: %s", writeFunc)
	}

	readSymbol := symTable.LookupFunc(readFunc)
	if readSymbol == nil {
		return fmt.Errorf("read function symbol not found: %s", readFunc)
	}

	// Master secret function is optional (only used in keylog mode)
	masterSecretSymbol := symTable.LookupFunc(masterSecretFunc)
	if masterSecretSymbol != nil {
		c.GoTlsMasterSecretAddr = c.addrToOffset(elfFile, masterSecretSymbol.Entry)
	}

	// Convert virtual addresses to file offsets
	c.GoTlsWriteAddr = c.addrToOffset(elfFile, writeSymbol.Entry)

	// For read function, use the entry point as the offset
	// In a full implementation, we would parse instructions to find RET offsets
	readOffset := c.addrToOffset(elfFile, readSymbol.Entry)
	c.ReadTlsAddrs = []uint64{readOffset}

	return nil
}

// readGoSymbolTable reads the Go symbol table from the ELF file
func (c *Config) readGoSymbolTable(elfFile *elf.File, goVersion string) (*gosym.Table, error) {
	// Try different section names for gopclntab
	sectionNames := []string{".gopclntab", ".data.rel.ro.gopclntab", ".data.rel.ro"}

	var pclnData []byte
	for _, name := range sectionNames {
		section := elfFile.Section(name)
		if section != nil {
			data, err := section.Data()
			if err != nil {
				continue
			}

			// Find gopclntab by magic number
			magic := magicNumber(goVersion)
			index := bytes.Index(data, magic)
			if index >= 0 {
				pclnData = data[index:]
				break
			}
		}
	}

	if pclnData == nil {
		return nil, fmt.Errorf("gopclntab not found in ELF file")
	}

	// Extract text start address from pclntab
	ptrSize := uint32(pclnData[7])
	var textStart uint64
	if ptrSize == 4 {
		textStart = uint64(binary.LittleEndian.Uint32(pclnData[8+2*ptrSize:]))
	} else {
		textStart = binary.LittleEndian.Uint64(pclnData[8+2*ptrSize:])
	}

	// Create line table and symbol table
	lineTable := gosym.NewLineTable(pclnData, textStart)
	symTable, err := gosym.NewTable([]byte{}, lineTable)
	if err != nil {
		return nil, fmt.Errorf("failed to create symbol table: %w", err)
	}

	return symTable, nil
}

// magicNumber returns the magic number for the given Go version
func magicNumber(goVersion string) []byte {
	const (
		go12magic  = 0xfffffffb
		go116magic = 0xfffffffa
		go118magic = 0xfffffff0
		go120magic = 0xfffffff1
	)

	bs := make([]byte, 4)
	var magic uint32

	if strings.Compare(goVersion, "go1.20") >= 0 {
		magic = go120magic
	} else if strings.Compare(goVersion, "go1.18") >= 0 {
		magic = go118magic
	} else if strings.Compare(goVersion, "go1.16") >= 0 {
		magic = go116magic
	} else {
		magic = go12magic
	}

	binary.LittleEndian.PutUint32(bs, magic)
	return bs
}

// addrToOffset converts a virtual address to a file offset
func (c *Config) addrToOffset(elfFile *elf.File, addr uint64) uint64 {
	// Find the program segment containing this address
	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= addr && addr < (prog.Vaddr+prog.Memsz) {
			// Convert virtual address to file offset
			return addr - prog.Vaddr + prog.Off
		}
	}

	// If not found in any segment, return the address directly
	return addr
}

// GetCaptureMode returns the capture mode (text, keylog, or pcap).
func (c *Config) GetCaptureMode() string {
	return c.CaptureMode
}

// GetPcapFile returns the pcap file path.
func (c *Config) GetPcapFile() string {
	return c.PcapFile
}

// GetKeylogFile returns the keylog file path.
func (c *Config) GetKeylogFile() string {
	return c.KeylogFile
}
