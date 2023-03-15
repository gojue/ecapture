// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Copyright © 2022 Hengqi Chen
package config

import (
	"errors"
	"os"
)

var (
	ErrorGoBINNotSET = errors.New("GO binary not set")
)

// GoTLSConfig represents configuration for Go SSL probe
type GoTLSConfig struct {
	eConfig
	Path   string `json:"path"`   // path to binary built with Go toolchain.
	Write  string `json:"write"`  // Write  the  raw  packets  to file rather than parsing and printing them out.
	Ifname string `json:"ifName"` // (TC Classifier) Interface name on which the probe will be attached.
	Port   uint16 `json:"port"`   // capture port
}

// NewGoTLSConfig creates a new config for Go SSL
func NewGoTLSConfig() *GoTLSConfig {
	return &GoTLSConfig{}
}

func (c *GoTLSConfig) Check() error {
	if c.Path == "" {
		return ErrorGoBINNotSET
	}

	if c.Ifname == "" || len(c.Ifname) == 0 {
		c.Ifname = DefaultIfname
	}

	_, err := os.Stat(c.Path)
	return err
}
