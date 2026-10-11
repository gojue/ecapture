// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
)

// CommonConfig contains the serializable settings shared by every probe
// generation. Process-lifetime output dependencies (the operational logger and
// typed captured-event publishers) deliberately live in output.RuntimeDependencies
// instead and are never copied through this type.
type CommonConfig struct {
	Pid                uint64
	Uid                uint64
	Debug              bool
	Hex                bool
	BTFMode            uint8
	ByteCodeFileMode   uint8
	PerCpuMapSize      int
	TruncateSize       uint64
	EventCollectorAddr string
	EventRotateSizeMB  uint16
	EventRotateSeconds uint16
	CGroupPath         string
	PerfReorder        bool
	PerfReorderLagMs   uint
}

// CommonConfigPatch records both a JSON value and whether the caller supplied
// it. Pointer fields are required so an HTTP reload can distinguish an omitted
// field from an explicit zero value or empty destination.
type CommonConfigPatch struct {
	Pid                *uint64 `json:"pid"`
	Uid                *uint64 `json:"uid"`
	Debug              *bool   `json:"debug"`
	Hex                *bool   `json:"is_hex"`
	BTFMode            *uint8  `json:"btf_mode"`
	ByteCodeFileMode   *uint8  `json:"byte_code_file_mode"`
	PerCpuMapSize      *int    `json:"per_cpu_map_size"`
	TruncateSize       *uint64 `json:"truncate_size"`
	EventCollectorAddr *string `json:"event_collector_addr"`
	EventRotateSizeMB  *uint16 `json:"event_rotate_size_mb"`
	EventRotateSeconds *uint16 `json:"event_rotate_seconds"`
	CGroupPath         *string `json:"cgroup_path"`
	PerfReorder        *bool   `json:"perf_reorder"`
	PerfReorderLagMs   *uint   `json:"perf_reorder_lag_ms"`
}

// BaseConfigProvider is implemented by BaseConfig and, through embedding, by
// every concrete probe configuration.
type BaseConfigProvider interface {
	GetBaseConfig() *BaseConfig
}

// BaseConfigFor returns the common configuration owned by value.
func BaseConfigFor(value any) (*BaseConfig, error) {
	provider, ok := value.(BaseConfigProvider)
	if !ok {
		return nil, fmt.Errorf("configuration %T does not expose a base config", value)
	}
	base := provider.GetBaseConfig()
	if base == nil {
		return nil, fmt.Errorf("configuration %T has a nil base config", value)
	}
	return base, nil
}

// CommonConfigFrom snapshots the serializable common probe settings.
func CommonConfigFrom(value any) (CommonConfig, error) {
	base, err := BaseConfigFor(value)
	if err != nil {
		return CommonConfig{}, err
	}
	return CommonConfig{
		Pid:                base.Pid,
		Uid:                base.Uid,
		Debug:              base.Debug,
		Hex:                base.IsHex,
		BTFMode:            base.BtfMode,
		ByteCodeFileMode:   base.ByteCodeFileMode,
		PerCpuMapSize:      base.PerCpuMapSize,
		TruncateSize:       base.TruncateSize,
		EventCollectorAddr: base.EventCollectorAddr,
		EventRotateSizeMB:  base.EventRotateSizeMB,
		EventRotateSeconds: base.EventRotateSeconds,
		CGroupPath:         base.CGroupPath,
		PerfReorder:        base.PerfReorder,
		PerfReorderLagMs:   base.PerfReorderLagMs,
	}, nil
}

// ApplyCommonConfig applies all serializable common probe settings in one
// operation. It only mutates fields and never validates or creates output
// sinks, so repeated application is safe.
func ApplyCommonConfig(target any, common CommonConfig) error {
	base, err := BaseConfigFor(target)
	if err != nil {
		return err
	}
	base.Pid = common.Pid
	base.Uid = common.Uid
	base.Debug = common.Debug
	base.IsHex = common.Hex
	base.BtfMode = common.BTFMode
	base.ByteCodeFileMode = common.ByteCodeFileMode
	base.PerCpuMapSize = common.PerCpuMapSize
	base.TruncateSize = common.TruncateSize
	base.EventCollectorAddr = common.EventCollectorAddr
	base.EventRotateSizeMB = common.EventRotateSizeMB
	base.EventRotateSeconds = common.EventRotateSeconds
	base.CGroupPath = common.CGroupPath
	base.PerfReorder = common.PerfReorder
	base.PerfReorderLagMs = common.PerfReorderLagMs
	return nil
}

// DecodeCommonConfigPatch extracts common JSON fields while retaining field
// presence. Concrete config factories decode the same request body for their
// module-specific fields.
func DecodeCommonConfigPatch(data []byte) (CommonConfigPatch, error) {
	var patch CommonConfigPatch
	if err := json.Unmarshal(data, &patch); err != nil {
		return CommonConfigPatch{}, err
	}
	return patch, nil
}

// Apply overlays fields supplied by the patch on the target's current common
// settings. Omitted fields remain unchanged.
func (p CommonConfigPatch) Apply(target any) error {
	common, err := CommonConfigFrom(target)
	if err != nil {
		return err
	}
	if p.Pid != nil {
		common.Pid = *p.Pid
	}
	if p.Uid != nil {
		common.Uid = *p.Uid
	}
	if p.Debug != nil {
		common.Debug = *p.Debug
	}
	if p.Hex != nil {
		common.Hex = *p.Hex
	}
	if p.BTFMode != nil {
		common.BTFMode = *p.BTFMode
	}
	if p.ByteCodeFileMode != nil {
		common.ByteCodeFileMode = *p.ByteCodeFileMode
	}
	if p.PerCpuMapSize != nil {
		common.PerCpuMapSize = *p.PerCpuMapSize
	}
	if p.TruncateSize != nil {
		common.TruncateSize = *p.TruncateSize
	}
	if p.EventCollectorAddr != nil {
		common.EventCollectorAddr = *p.EventCollectorAddr
	}
	if p.EventRotateSizeMB != nil {
		common.EventRotateSizeMB = *p.EventRotateSizeMB
	}
	if p.EventRotateSeconds != nil {
		common.EventRotateSeconds = *p.EventRotateSeconds
	}
	if p.CGroupPath != nil {
		common.CGroupPath = *p.CGroupPath
	}
	if p.PerfReorder != nil {
		common.PerfReorder = *p.PerfReorder
	}
	if p.PerfReorderLagMs != nil {
		common.PerfReorderLagMs = *p.PerfReorderLagMs
	}
	return ApplyCommonConfig(target, common)
}

// MergeReloadOutput applies the reload inheritance contract for captured-event
// output. Only omitted fields inherit; explicit empty and zero values are kept.
// Other common fields retain the concrete config factory's normal defaults or
// explicitly decoded values.
func MergeReloadOutput(current, candidate any, patch CommonConfigPatch) error {
	currentBase, err := BaseConfigFor(current)
	if err != nil {
		return err
	}
	candidateBase, err := BaseConfigFor(candidate)
	if err != nil {
		return err
	}
	if patch.EventCollectorAddr == nil {
		candidateBase.EventCollectorAddr = currentBase.EventCollectorAddr
	}
	if patch.EventRotateSizeMB == nil {
		candidateBase.EventRotateSizeMB = currentBase.EventRotateSizeMB
	}
	if patch.EventRotateSeconds == nil {
		candidateBase.EventRotateSeconds = currentBase.EventRotateSeconds
	}
	return nil
}
