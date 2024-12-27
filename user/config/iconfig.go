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

package config

import (
	"encoding/json"
	"os"

	"github.com/gojue/ecapture/pkg/util/kernel"
)

// IConfig defines the interface for configuration management
type IConfig interface {
	// Check validates the configuration settings
	Check() error
	// GetPid returns the process ID to monitor
	GetPid() uint64
	// GetUid returns the user ID to monitor
	GetUid() uint64
	// GetHex returns whether to display output in hexadecimal format
	GetHex() bool
	// GetBTF returns the BTF (BPF Type Format) mode
	GetBTF() uint8
	// GetDebug returns whether debug mode is enabled
	GetDebug() bool
	// GetByteCodeFileMode returns the bytecode file mode
	GetByteCodeFileMode() uint8
	// SetPid sets the process ID to monitor
	SetPid(uint64)
	// SetUid sets the user ID to monitor
	SetUid(uint64)
	// SetHex sets whether to display output in hexadecimal format
	SetHex(bool)
	// SetBTF sets the BTF (BPF Type Format) mode
	SetBTF(uint8)
	// SetByteCodeFileMode sets the bytecode file mode
	SetByteCodeFileMode(uint8)
	// SetDebug enables or disables debug mode
	SetDebug(bool)
	// SetAddrType sets the logger output type
	SetAddrType(uint8)
	// SetEventCollectorAddr sets the address for the event collector
	SetEventCollectorAddr(string)
	// GetEventCollectorAddr returns the event collector address
	GetEventCollectorAddr() string
	// GetPerCpuMapSize returns the eBPF map size per CPU
	GetPerCpuMapSize() int
	// SetPerCpuMapSize sets the eBPF map size per CPU
	SetPerCpuMapSize(int)
	// EnableGlobalVar checks if global variables are supported based on kernel version
	EnableGlobalVar() bool
	// Bytes serializes the configuration to JSON bytes
	Bytes() []byte
}

// TLS capture mode constants defining different output formats
const (
	TlsCaptureModelText   = "text"   // Plain text output
	TlsCaptureModelPcap   = "pcap"   // PCAP format output
	TlsCaptureModelPcapng = "pcapng" // PCAPNG format output
	TlsCaptureModelKey    = "key"    // Key only output
	TlsCaptureModelKeylog = "keylog" // Key log format output
)

// BTF mode constants for BPF Type Format handling
const (
	BTFModeAutoDetect = 0 // Automatically detect BTF availability
	BTFModeCore       = 1 // Use kernel BTF
	BTFModeNonCore    = 2 // Use non-kernel BTF
)

// ByteCodeFileMode defines the mode for bytecode file selection
const (
	ByteCodeFileAll     = 0 // Use all bytecode files
	ByteCodeFileCore    = 1 // Use kernel bytecode file
	ByteCodeFileNonCore = 2 // Use non-kernel bytecode file
)

// BaseConfig implements the IConfig interface and holds the basic configuration settings
type BaseConfig struct {
	Pid    uint64 `json:"pid"`    // Process ID to monitor
	Uid    uint64 `json:"uid"`    // User ID to monitor
	Listen string `json:"listen"` // Listen address for the server (default: 127.0.0.1:28256)

	// eBPF map configuration
	PerCpuMapSize      int    `json:"per_cpu_map_size"`     // Size of eBPF map per CPU core
	IsHex              bool   `json:"is_hex"`               // Whether to display output in hexadecimal
	Debug              bool   `json:"debug"`                // Enable debug mode
	BtfMode            uint8  `json:"btf_mode"`             // BTF mode selection
	ByteCodeFileMode   uint8  `json:"byte_code_file_mode"`  // assets/* include bytecode file type
	LoggerAddr         string `json:"logger_addr"`          // Address for logger output
	LoggerType         uint8  `json:"logger_type"`          // Logger type (0:stdout, 1:file, 2:tcp)
	EventCollectorAddr string `json:"event_collector_addr"` // Address of the event collector server
}

func (c *BaseConfig) GetPid() uint64 {
	return c.Pid
}

func (c *BaseConfig) GetUid() uint64 {
	return c.Uid
}

func (c *BaseConfig) GetDebug() bool {
	return c.Debug
}

func (c *BaseConfig) GetHex() bool {
	return c.IsHex
}

func (c *BaseConfig) SetPid(pid uint64) {
	c.Pid = pid
}

func (c *BaseConfig) SetUid(uid uint64) {
	c.Uid = uid
}

func (c *BaseConfig) SetEventCollectorAddr(addr string) {
	c.EventCollectorAddr = addr
}

func (c *BaseConfig) GetEventCollectorAddr() string {
	return c.EventCollectorAddr
}

func (c *BaseConfig) SetAddrType(t uint8) {
	c.LoggerType = t
}

func (c *BaseConfig) SetDebug(b bool) {
	c.Debug = b
}

func (c *BaseConfig) SetHex(isHex bool) {
	c.IsHex = isHex
}

func (c *BaseConfig) SetBTF(BtfMode uint8) {
	c.BtfMode = BtfMode
}

func (c *BaseConfig) GetBTF() uint8 {
	return c.BtfMode
}

func (c *BaseConfig) SetByteCodeFileMode(mode uint8) {
	c.ByteCodeFileMode = mode
}

func (c *BaseConfig) GetByteCodeFileMode() uint8 {
	return c.ByteCodeFileMode
}

func (c *BaseConfig) GetPerCpuMapSize() int {
	return c.PerCpuMapSize
}

func (c *BaseConfig) SetPerCpuMapSize(size int) {
	c.PerCpuMapSize = size * os.Getpagesize()
}

func (c *BaseConfig) EnableGlobalVar() bool {
	kv, err := kernel.HostVersion()
	if err != nil {
		return true
	}
	if kv < kernel.VersionCode(5, 2, 0) {
		return false
	}
	return true
}

func (c *BaseConfig) Bytes() []byte {
	b, e := json.Marshal(c)
	if e != nil {
		return []byte{}
	}
	return b
}
