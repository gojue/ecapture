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

package builder

import (
	"github.com/gojue/ecapture/internal/config"
)

// ConfigBuilder provides a fluent interface for building probe configurations.
type ConfigBuilder struct {
	config *config.BaseConfig
}

// NewConfigBuilder creates a new ConfigBuilder with default values.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: config.NewBaseConfig(),
	}
}

// WithPid sets the target process ID.
func (b *ConfigBuilder) WithPid(pid uint64) *ConfigBuilder {
	b.config.SetPid(pid)
	return b
}

// WithUid sets the target user ID.
func (b *ConfigBuilder) WithUid(uid uint64) *ConfigBuilder {
	b.config.SetUid(uid)
	return b
}

// WithDebug enables or disables debug mode.
func (b *ConfigBuilder) WithDebug(debug bool) *ConfigBuilder {
	b.config.SetDebug(debug)
	return b
}

// WithHex enables or disables hexadecimal output.
func (b *ConfigBuilder) WithHex(hex bool) *ConfigBuilder {
	b.config.SetHex(hex)
	return b
}

// WithBTF sets the BTF mode.
func (b *ConfigBuilder) WithBTF(mode uint8) *ConfigBuilder {
	b.config.SetBTF(mode)
	return b
}

// WithByteCodeFileMode sets the bytecode file mode.
func (b *ConfigBuilder) WithByteCodeFileMode(mode uint8) *ConfigBuilder {
	b.config.SetByteCodeFileMode(mode)
	return b
}

// WithPerCpuMapSize sets the eBPF map size per CPU.
func (b *ConfigBuilder) WithPerCpuMapSize(size int) *ConfigBuilder {
	b.config.SetPerCpuMapSize(size)
	return b
}

// WithTruncateSize sets the truncate size for captured data.
func (b *ConfigBuilder) WithTruncateSize(size uint64) *ConfigBuilder {
	b.config.SetTruncateSize(size)
	return b
}

// Build validates and returns the built configuration.
func (b *ConfigBuilder) Build() (*config.BaseConfig, error) {
	if err := b.config.Validate(); err != nil {
		return nil, err
	}
	return b.config, nil
}

// MustBuild builds the configuration and panics on error.
// Use this only when you are certain the configuration is valid.
func (b *ConfigBuilder) MustBuild() *config.BaseConfig {
	cfg, err := b.Build()
	if err != nil {
		panic(err)
	}
	return cfg
}
