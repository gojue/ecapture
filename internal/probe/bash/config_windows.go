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

package bash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	ElfTypeBin = 1
	ElfTypeSo  = 2
)

// Config extends BaseConfig with Bash/PowerShell-specific configuration for Windows.
type Config struct {
	*config.BaseConfig
	Bashpath         string `json:"bashpath"` // Path to shell binary (PowerShell/cmd)
	Readline         string `json:"readline"` // Not used on Windows
	ErrNo            int    `json:"errno"`
	ElfType          uint8  `json:"elf_type"`
	ReadlineFuncName string `json:"readline_func_name"`

	// Windows-specific fields
	ShellType     string `json:"shell_type"`     // "powershell", "cmd", or "bash" (WSL/Git Bash)
	PowerShellVer string `json:"powershell_ver"` // PowerShell version
}

// NewConfig creates a new Bash probe configuration for Windows.
func NewConfig() *Config {
	return &Config{
		BaseConfig: config.NewBaseConfig(),
		ErrNo:      128,
	}
}

// Validate checks if the configuration is valid on Windows.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("bash config validation failed", err)
	}

	// Detect shell on Windows
	if err := c.checkElf(); err != nil {
		return errors.NewConfigurationError("shell detection failed", err)
	}

	return nil
}

// checkElf detects the shell binary on Windows.
func (c *Config) checkElf() error {
	// If a specific shell is configured
	if p := strings.TrimSpace(c.Bashpath); p != "" {
		if _, err := os.Stat(c.Bashpath); err != nil {
			return errors.Wrap(errors.ErrCodeConfiguration, "shell path not found", err).
				WithContext("path", c.Bashpath)
		}
		c.ShellType = detectShellType(c.Bashpath)
		c.ElfType = ElfTypeBin
		return nil
	}

	// Try PowerShell first (most common on Windows)
	powershellPaths := []string{
		`C:\Program Files\PowerShell\7\pwsh.exe`,
		`C:\Program Files\PowerShell\6\pwsh.exe`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}

	for _, path := range powershellPaths {
		if _, err := os.Stat(path); err == nil {
			c.Bashpath = path
			c.ShellType = "powershell"
			c.ElfType = ElfTypeBin
			return nil
		}
	}

	// Try cmd.exe
	cmdPath := `C:\Windows\System32\cmd.exe`
	if _, err := os.Stat(cmdPath); err == nil {
		c.Bashpath = cmdPath
		c.ShellType = "cmd"
		c.ElfType = ElfTypeBin
		return nil
	}

	// Try Git Bash or WSL bash
	bashPaths := []string{
		`C:\Program Files\Git\bin\bash.exe`,
		`C:\Program Files (x86)\Git\bin\bash.exe`,
		`C:\Windows\System32\bash.exe`, // WSL
	}

	for _, path := range bashPaths {
		if _, err := os.Stat(path); err == nil {
			c.Bashpath = path
			c.ShellType = "bash"
			c.ElfType = ElfTypeBin
			return nil
		}
	}

	return errors.New(errors.ErrCodeConfiguration, "cannot find a valid shell binary on Windows")
}

// detectShellType determines the shell type from the binary path.
func detectShellType(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "pwsh") || strings.Contains(base, "powershell"):
		return "powershell"
	case strings.Contains(base, "cmd"):
		return "cmd"
	case strings.Contains(base, "bash"):
		return "bash"
	default:
		return "unknown"
	}
}

// Bytes serializes the configuration to JSON.
func (c *Config) Bytes() []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return []byte{}
	}
	return b
}
