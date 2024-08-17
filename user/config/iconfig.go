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
	SetEventCollectorAddr(string)
	GetEventCollectorAddr() string
	GetPerCpuMapSize() int
	SetPerCpuMapSize(int)
	EnableGlobalVar() bool //
	Bytes() []byte
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
	Pid    uint64 `json:"pid"`
	Uid    uint64 `json:"uid"`
	Listen string `json:"listen"` // listen address, default: 127.0.0.1:28256

	// mapSizeKB
	PerCpuMapSize      int    `json:"per_cpu_map_size"` // ebpf map size for per Cpu.   see https://github.com/gojue/ecapture/issues/433 .
	IsHex              bool   `json:"is_hex"`
	Debug              bool   `json:"debug"`
	BtfMode            uint8  `json:"btf_mode"`
	LoggerAddr         string `json:"logger_addr"`          // logger address
	LoggerType         uint8  `json:"logger_type"`          // 0:stdout, 1:file, 2:tcp
	EventCollectorAddr string `json:"event_collector_addr"` // the server address that receives the captured event
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
