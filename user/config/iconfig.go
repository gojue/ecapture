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
	"github.com/gojue/ecapture/pkg/util/kernel"
	"os"
)

type IConfig interface {
	Check() error //检测配置合法性
	GetPid() uint64
	GetUid() uint64
	GetHex() bool
	GetBTF() uint8
	GetDebug() bool
	SetPid(uint64)
	SetUid(uint64)
	SetHex(bool)
	SetBTF(uint8)
	SetDebug(bool)
	SetAddrType(uint8)
	SetAddress(string)
	GetAddress() string
	GetPerCpuMapSize() int
	SetPerCpuMapSize(int)
	EnableGlobalVar() bool //
}

const (
	TlsCaptureModelText   = "text"
	TlsCaptureModelPcap   = "pcap"
	TlsCaptureModelPcapng = "pcapng"
	TlsCaptureModelKey    = "key"
	TlsCaptureModelKeylog = "keylog"
)

const (
	BTFModeAutoDetect = 0
	BTFModeCore       = 1
	BTFModeNonCore    = 2
)

type BaseConfig struct {
	Pid uint64 `json:"pid,omitempty"`
	Uid uint64 `json:"uid,omitempty"`

	// mapSizeKB
	PerCpuMapSize int    `json:"per_cpu_map_size,omitempty"` // ebpf map size for per Cpu.   see https://github.com/gojue/ecapture/issues/433 .
	IsHex         bool   `json:"is_hex,omitempty"`
	Debug         bool   `json:"debug,omitempty"`
	BtfMode       uint8  `json:"btf_mode,omitempty"`
	AddrType      uint8  `json:"addr_type,omitempty"` // 0:stdout, 1:file, 2:tcp
	Address       string `json:"address,omitempty"`
	LoggerAddr    string `json:"logger_addr,omitempty"` // save file
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

func (c *BaseConfig) SetAddress(addr string) {
	c.Address = addr
}

func (c *BaseConfig) GetAddress() string {
	return c.Address
}

func (c *BaseConfig) SetAddrType(t uint8) {
	c.AddrType = t
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

func (c *BaseConfig) GetPerCpuMapSize() int {
	return c.PerCpuMapSize
}

func (c *BaseConfig) SetPerCpuMapSize(size int) {
	c.PerCpuMapSize = size * os.Getpagesize()
}

func (c *BaseConfig) EnableGlobalVar() bool {
	kv, err := kernel.HostVersion()
	if err != nil {
		//log.Fatal(err)
		return true
	}
	if kv < kernel.VersionCode(5, 2, 0) {
		return false
	}
	return true
}
