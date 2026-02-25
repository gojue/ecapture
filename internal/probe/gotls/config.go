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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
	"github.com/gojue/ecapture/pkg/proc"
)

var (
	ErrorGoBinNotFound            = errors.New("the executable program (compiled by Golang) was not found")
	ErrorSymbolEmpty              = errors.New("symbol is empty")
	ErrorSymbolNotFound           = errors.New("symbol not found")
	ErrorSymbolNotFoundFromTable  = errors.New("symbol not found from table")
	ErrorNoRetFound               = errors.New("no RET instructions found")
	ErrorNoFuncFoundFromSymTabFun = errors.New("no function found from golang symbol table with Func Name")
	ErrorTextSectionNotFound      = errors.New("`.text` section not found")
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
	ReadTlsAddrs []int `json:"-"`

	// GoTlsWriteAddr stores the offset for Write function
	GoTlsWriteAddr uint64 `json:"-"`

	// GoTlsMasterSecretAddr stores the offset for master secret function (keylog mode)
	GoTlsMasterSecretAddr uint64 `json:"-"`

	// BuildInfo stores the build info from the Go binary (for debugging)
	BuildInfo *buildinfo.BuildInfo `json:"build_info"`

	// IsPieBuildMode indicates whether the Go binary is built in PIE mode (position-independent executable)
	IsPieBuildMode bool `json:"is_pie_build_mode"`

	goSymTab  *gosym.Table
	goElfArch string    //
	goElf     *elf.File //
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

	// Parse the Go ELF file to detect Go version and symbol addresses
	if err := c.parserGoElf(); err != nil {
		return fmt.Errorf("failed to parse Go ELF file: %w", err)
	}

	// Validate the rest of the configuration
	if err := c.validateConf(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return err
	}

	return nil
}

func (c *Config) parserGoElf() error {
	// Detect Go version
	if c.ElfPath == "" {
		return fmt.Errorf("no ELF path specified")
	}
	var err error
	_, err = os.Stat(c.ElfPath)
	if err != nil {
		return err
	}

	// Read the build information of the Go application
	c.BuildInfo, err = buildinfo.ReadFile(c.ElfPath)
	if err != nil {
		return err
	}

	ver, err := proc.ExtraceGoVersion(c.ElfPath)
	if err != nil {
		return err
	}

	// supported at 1.17 via https://github.com/golang/go/issues/40724
	if ver.After(1, 17) {
		c.IsRegisterABI = true
	}

	var goElf *elf.File
	goElf, err = elf.Open(c.ElfPath)
	if err != nil {
		return err
	}

	var goElfArch, machineStr string
	machineStr = goElf.FileHeader.Machine.String()
	switch machineStr {
	case elf.EM_AARCH64.String():
		goElfArch = "arm64"
	case elf.EM_X86_64.String():
		goElfArch = "amd64"
	default:
		goElfArch = "unsupported_arch"
	}

	if goElfArch != runtime.GOARCH {
		err = fmt.Errorf("go Application not match, want:%s, have:%s", runtime.GOARCH, goElfArch)
		return err
	}
	switch goElfArch {
	case "amd64":
	case "arm64":
	default:
		return fmt.Errorf("unsupport CPU arch :%s", goElfArch)
	}
	c.goElfArch = goElfArch
	c.goElf = goElf
	// If built with PIE and stripped, gopclntab is
	// unlabeled and nested under .data.rel.ro.
	for _, bs := range c.BuildInfo.Settings {
		if bs.Key == "-buildmode" {
			if bs.Value == "pie" {
				c.IsPieBuildMode = true
			}
			break
		}
	}

	c.goSymTab, err = c.ReadTable()
	if err != nil {
		return err
	}

	if c.IsPieBuildMode {
		var addr uint64
		addr, err = c.findPieSymbolAddr(GoTlsWriteFunc)
		if err != nil {
			return fmt.Errorf("%s symbol address error:%s", GoTlsWriteFunc, err.Error())
		}
		c.GoTlsWriteAddr = addr
		addr, err = c.findPieSymbolAddr(GoTlsMasterSecretFunc)
		if err != nil {
			return fmt.Errorf("%s symbol address error:%s", GoTlsMasterSecretFunc, err.Error())
		}
		c.GoTlsMasterSecretAddr = addr

		c.ReadTlsAddrs, err = c.findRetOffsetsPie(GoTlsReadFunc)
		if err != nil {
			return err
		}
	} else {
		var addr uint64
		addr, err = c.findSymbolAddr(GoTlsWriteFunc)
		if err != nil {
			return fmt.Errorf("%s find symbol addr error:%w", GoTlsWriteFunc, err)
		}
		c.GoTlsWriteAddr = addr

		addr, err = c.findSymbolAddr(GoTlsMasterSecretFunc)
		if err != nil {
			return fmt.Errorf("%s find symbol addr error:%w", GoTlsMasterSecretFunc, err)
		}
		c.GoTlsMasterSecretAddr = addr

		c.ReadTlsAddrs, err = c.findRetOffsets(GoTlsReadFunc)
		if err == nil {
			return nil
		}
		c.ReadTlsAddrs, err = c.findSymbolRetOffsets(GoTlsReadFunc)
		if err != nil {
			return err
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

	case handlers.ModePcap, handlers.ModePcapng:
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

	addrs, err := iface.Addrs() // Just to check if we can access interface addresses (basic functionality check)
	if err != nil {
		return fmt.Errorf("cannot access addresses for interface '%s': %w", c.Ifname, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("network interface '%s' has no addresses", c.Ifname)
	}

	return nil
}

func (c *Config) validateConf() error {
	if c.GoTlsMasterSecretAddr <= 0 {
		return fmt.Errorf("goTlsMasterSecretAddr must be > 0")
	}

	if c.GoTlsWriteAddr <= 0 {
		return fmt.Errorf("goTlsWriteAddr must be > 0")
	}

	if len(c.ReadTlsAddrs) == 0 {
		return fmt.Errorf("readTlsAddrs must not be empty")
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
