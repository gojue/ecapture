//go:build windows
// +build windows

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
	"encoding/json"
	"fmt"
	"os"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

// Config extends BaseConfig with Go TLS-specific configuration for Windows.
type Config struct {
	*config.BaseConfig
	Path        string `json:"path"`        // Path to Go binary
	CaptureMode string `json:"capturemode"` // "text", "keylog", or "pcap"
	KeylogFile  string `json:"keylogfile"`
	PcapFile    string `json:"pcapfile"`
	Ifname      string `json:"ifname"`
	PcapFilter  string `json:"pcapfilter"`
	CGroupPath  string `json:"cgroup_path"`
}

// NewConfig creates a new GoTLS probe configuration for Windows.
func NewConfig() *Config {
	return &Config{
		BaseConfig:  config.NewBaseConfig(),
		CaptureMode: "text",
	}
}

// Validate checks if the configuration is valid on Windows.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("gotls config validation failed", err)
	}

	if c.Path == "" {
		return errors.NewConfigurationError("Go binary path is required", nil)
	}

	if _, err := os.Stat(c.Path); err != nil {
		return errors.NewConfigurationError(fmt.Sprintf("Go binary not found: %s", c.Path), err)
	}

	return nil
}

// Bytes serializes the configuration to JSON.
func (c *Config) Bytes() []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return []byte{}
	}
	return b
}
