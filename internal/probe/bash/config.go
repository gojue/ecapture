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

package bash

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	fallbackBashPath = "/bin/bash"
	ElfTypeBin       = 1
	ElfTypeSo        = 2
)

// Config extends BaseConfig with Bash-specific configuration.
type Config struct {
	*config.BaseConfig
	Bashpath         string `json:"bashpath"` // Path to bash binary
	Readline         string `json:"readline"` // Path to libreadline.so
	ErrNo            int    `json:"errno"`
	ElfType          uint8  `json:"elf_type"`
	ReadlineFuncName string `json:"readline_func_name"`
}

// NewConfig creates a new Bash probe configuration.
func NewConfig() *Config {
	return &Config{
		BaseConfig: config.NewBaseConfig(),
		ErrNo:      128, // Default errno for bash
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("bash config validation failed", err)
	}

	// Check ELF paths
	if err := c.checkElf(); err != nil {
		return errors.NewConfigurationError("bash elf check failed", err)
	}

	// Check readline function
	if err := c.checkReadlineFunc(); err != nil {
		return errors.NewConfigurationError("bash readline check failed", err)
	}

	return nil
}

// checkElf validates and detects bash and readline paths.
func (c *Config) checkElf() error {
	// If readline is configured
	if c.Readline != "" && len(strings.TrimSpace(c.Readline)) > 0 {
		if _, err := os.Stat(c.Readline); err != nil {
			return fmt.Errorf("readline path not found: %w", err)
		}
		c.ElfType = ElfTypeSo
		return nil
	}

	// If bash path is configured
	if c.Bashpath != "" && len(strings.TrimSpace(c.Bashpath)) > 0 {
		if _, err := os.Stat(c.Bashpath); err != nil {
			return fmt.Errorf("bash path not found: %w", err)
		}
		c.ElfType = ElfTypeBin
		return nil
	}

	// Auto-detect bash path
	if bash, found := os.LookupEnv("SHELL"); found && strings.Contains(bash, "bash") {
		c.Bashpath = bash
		if soPath, err := getDynPathByElf(bash, "libreadline.so"); err == nil {
			c.Readline = soPath
			c.ElfType = ElfTypeSo
		} else {
			c.ElfType = ElfTypeBin
		}
		return nil
	}

	// Try fallback path
	if _, err := os.Stat(fallbackBashPath); err == nil {
		c.Bashpath = fallbackBashPath
		if soPath, err := getDynPathByElf(fallbackBashPath, "libreadline.so"); err == nil {
			c.Readline = soPath
			c.ElfType = ElfTypeSo
		} else {
			c.ElfType = ElfTypeBin
		}
		return nil
	}

	return fmt.Errorf("cannot find valid bash path in $SHELL or %s", fallbackBashPath)
}

// checkReadlineFunc determines which readline function to hook.
func (c *Config) checkReadlineFunc() error {
	var binaryPath string
	switch c.ElfType {
	case ElfTypeBin:
		binaryPath = c.Bashpath
	case ElfTypeSo:
		binaryPath = c.Readline
	default:
		binaryPath = fallbackBashPath
	}

	file, err := elf.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to open binary %s: %w", binaryPath, err)
	}
	defer file.Close()

	symbols, err := file.DynamicSymbols()
	if err != nil {
		return fmt.Errorf("failed to read symbols from %s: %w", binaryPath, err)
	}

	// Check for preferred function
	targetSymbol := "readline_internal_teardown"
	for _, sym := range symbols {
		if sym.Name == targetSymbol {
			c.ReadlineFuncName = targetSymbol
			return nil
		}
	}

	// Fall back to standard readline
	c.ReadlineFuncName = "readline"
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

// getDynPathByElf finds a shared library path linked by an ELF binary.
func getDynPathByElf(elfPath, soName string) (string, error) {
	file, err := elf.Open(elfPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	libs, err := file.ImportedLibraries()
	if err != nil {
		return "", err
	}

	for _, lib := range libs {
		if strings.Contains(lib, soName) {
			// Try to find the full path
			// This is simplified - in production, would need to search library paths
			possiblePaths := []string{
				"/lib/x86_64-linux-gnu/" + lib,
				"/lib/aarch64-linux-gnu/" + lib,
				"/usr/lib/x86_64-linux-gnu/" + lib,
				"/usr/lib/aarch64-linux-gnu/" + lib,
				"/lib/" + lib,
				"/usr/lib/" + lib,
			}
			for _, path := range possiblePaths {
				if _, err := os.Stat(path); err == nil {
					return path, nil
				}
			}
		}
	}

	return "", fmt.Errorf("library %s not found in %s", soName, elfPath)
}
