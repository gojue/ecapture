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
	"fmt"
	"os"

	"github.com/gojue/ecapture/pkg/util/kernel"
)

// BTF mode constants
const (
	BTFModeAutoDetect = 0
	BTFModeCore       = 1
	BTFModeNonCore    = 2
)

// ByteCodeFileMode constants
const (
	ByteCodeFileAll     = 0
	ByteCodeFileCore    = 1
	ByteCodeFileNonCore = 2
)

// DefaultMapSizePerCpu is the default eBPF map size per CPU (8MB).
const DefaultMapSizePerCpu = 8 * 1024 * 1024

// BaseConfig provides common configuration for all probes.
type BaseConfig struct {
	Pid                uint64 `json:"pid"`
	Uid                uint64 `json:"uid"`
	Debug              bool   `json:"debug"`
	IsHex              bool   `json:"is_hex"`
	BtfMode            uint8  `json:"btf_mode"`
	ByteCodeFileMode   uint8  `json:"byte_code_file_mode"`
	PerCpuMapSize      int    `json:"per_cpu_map_size"`
	TruncateSize       uint64 `json:"truncate_size"`
	LoggerAddr         string `json:"logger_addr"`
	EventCollectorAddr string `json:"event_collector_addr"`
	EcaptureQ          string `json:"ecapture_q"`
	Listen             string `json:"listen"`
	AddrType           uint8  `json:"addr_type"`
}

// NewBaseConfig creates a new BaseConfig with default values.
func NewBaseConfig() *BaseConfig {
	return &BaseConfig{
		Pid:                0,
		Uid:                0,
		Debug:              false,
		IsHex:              false,
		BtfMode:            BTFModeAutoDetect,
		ByteCodeFileMode:   ByteCodeFileAll,
		PerCpuMapSize:      DefaultMapSizePerCpu,
		TruncateSize:       0,
		LoggerAddr:         "",
		EventCollectorAddr: "",
		EcaptureQ:          "",
		Listen:             "localhost:28256",
		AddrType:           0,
	}
}

// Validate checks if the configuration is valid.
func (c *BaseConfig) Validate() error {
	if c.PerCpuMapSize <= 0 {
		return fmt.Errorf("per_cpu_map_size must be positive, got %d", c.PerCpuMapSize)
	}
	if c.BtfMode > BTFModeNonCore {
		return fmt.Errorf("invalid btf_mode: %d", c.BtfMode)
	}
	if c.ByteCodeFileMode > ByteCodeFileNonCore {
		return fmt.Errorf("invalid byte_code_file_mode: %d", c.ByteCodeFileMode)
	}
	return nil
}

// GetPid returns the target process ID.
func (c *BaseConfig) GetPid() uint64 {
	return c.Pid
}

// GetUid returns the target user ID.
func (c *BaseConfig) GetUid() uint64 {
	return c.Uid
}

// GetDebug returns whether debug mode is enabled.
func (c *BaseConfig) GetDebug() bool {
	return c.Debug
}

// GetHex returns whether output should be in hexadecimal format.
func (c *BaseConfig) GetHex() bool {
	return c.IsHex
}

// GetBTF returns the BTF mode.
func (c *BaseConfig) GetBTF() uint8 {
	return c.BtfMode
}

// GetPerCpuMapSize returns the eBPF map size per CPU.
func (c *BaseConfig) GetPerCpuMapSize() int {
	return c.PerCpuMapSize
}

// GetTruncateSize returns the truncate size for captured data.
func (c *BaseConfig) GetTruncateSize() uint64 {
	return c.TruncateSize
}

// GetByteCodeFileMode returns the bytecode file selection mode.
func (c *BaseConfig) GetByteCodeFileMode() uint8 {
	return c.ByteCodeFileMode
}

// EnableGlobalVar checks if the kernel supports global variables.
func (c *BaseConfig) EnableGlobalVar() bool {
	kv, err := kernel.HostVersion()
	if err != nil {
		return true
	}
	return kv >= kernel.VersionCode(5, 2, 0)
}

// Bytes serializes the configuration to JSON.
func (c *BaseConfig) Bytes() []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return []byte{}
	}
	return b
}

// SetPid sets the target process ID.
func (c *BaseConfig) SetPid(pid uint64) {
	c.Pid = pid
}

// SetUid sets the target user ID.
func (c *BaseConfig) SetUid(uid uint64) {
	c.Uid = uid
}

// SetDebug sets the debug mode.
func (c *BaseConfig) SetDebug(debug bool) {
	c.Debug = debug
}

// SetHex sets the hex output mode.
func (c *BaseConfig) SetHex(hex bool) {
	c.IsHex = hex
}

// SetBTF sets the BTF mode.
func (c *BaseConfig) SetBTF(mode uint8) {
	c.BtfMode = mode
}

// SetByteCodeFileMode sets the bytecode file mode.
func (c *BaseConfig) SetByteCodeFileMode(mode uint8) {
	c.ByteCodeFileMode = mode
}

// SetPerCpuMapSize sets the eBPF map size per CPU.
func (c *BaseConfig) SetPerCpuMapSize(size int) {
	c.PerCpuMapSize = size * os.Getpagesize()
}

// SetTruncateSize sets the truncate size.
func (c *BaseConfig) SetTruncateSize(size uint64) {
	c.TruncateSize = size
}

// GetLoggerAddr returns the logger address.
func (c *BaseConfig) GetLoggerAddr() string {
	return c.LoggerAddr
}

// SetLoggerAddr sets the logger address.
func (c *BaseConfig) SetLoggerAddr(addr string) {
	c.LoggerAddr = addr
}

// GetEventCollectorAddr returns the event collector address.
func (c *BaseConfig) GetEventCollectorAddr() string {
	return c.EventCollectorAddr
}

// SetEventCollectorAddr sets the event collector address.
func (c *BaseConfig) SetEventCollectorAddr(addr string) {
	c.EventCollectorAddr = addr
}

// GetEcaptureQ returns the eCaptureQ address.
func (c *BaseConfig) GetEcaptureQ() string {
	return c.EcaptureQ
}

// SetEcaptureQ sets the eCaptureQ address.
func (c *BaseConfig) SetEcaptureQ(addr string) {
	c.EcaptureQ = addr
}

// GetListen returns the HTTP listen address.
func (c *BaseConfig) GetListen() string {
	return c.Listen
}

// SetListen sets the HTTP listen address.
func (c *BaseConfig) SetListen(addr string) {
	c.Listen = addr
}

// GetAddrType returns the logger address type.
func (c *BaseConfig) GetAddrType() uint8 {
	return c.AddrType
}

// SetAddrType sets the logger address type.
func (c *BaseConfig) SetAddrType(t uint8) {
	c.AddrType = t
}
