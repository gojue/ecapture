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
	GetDebug() bool
	SetPid(uint64)
	SetUid(uint64)
	SetHex(bool)
	SetDebug(bool)
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

type eConfig struct {
	Pid           uint64
	Uid           uint64
	PerCpuMapSize int // ebpf map size for per Cpu.   see https://github.com/gojue/ecapture/issues/433 .
	IsHex         bool
	Debug         bool
}

func (c *eConfig) GetPid() uint64 {
	return c.Pid
}

func (c *eConfig) GetUid() uint64 {
	return c.Uid
}

func (c *eConfig) GetDebug() bool {
	return c.Debug
}

func (c *eConfig) GetHex() bool {
	return c.IsHex
}

func (c *eConfig) SetPid(pid uint64) {
	c.Pid = pid
}

func (c *eConfig) SetUid(uid uint64) {
	c.Uid = uid
}

func (c *eConfig) SetDebug(b bool) {
	c.Debug = b
}

func (c *eConfig) SetHex(isHex bool) {
	c.IsHex = isHex
}

func (c *eConfig) GetPerCpuMapSize() int {
	return c.PerCpuMapSize
}

func (c *eConfig) SetPerCpuMapSize(size int) {
	c.PerCpuMapSize = size * os.Getpagesize()
}

func (c *eConfig) EnableGlobalVar() bool {
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
