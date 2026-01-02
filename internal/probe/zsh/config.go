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

package zsh

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
fallbackZshPath = "/bin/zsh"
ElfTypeBin      = 1
)

// Config extends BaseConfig with Zsh-specific configuration.
type Config struct {
*config.BaseConfig
Zshpath          string `json:"zshpath"` // Path to zsh binary
ErrNo            int    `json:"errno"`
ElfType          uint8  `json:"elf_type"`
ReadlineFuncName string `json:"readline_func_name"`
}

// NewConfig creates a new Zsh probe configuration.
func NewConfig() *Config {
return &Config{
BaseConfig: config.NewBaseConfig(),
ErrNo:      128,
}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
if err := c.BaseConfig.Validate(); err != nil {
return errors.NewConfigurationError("zsh config validation failed", err)
}

if err := c.checkElf(); err != nil {
return errors.NewConfigurationError("zsh elf check failed", err)
}

if err := c.checkReadlineFunc(); err != nil {
return errors.NewConfigurationError("zsh readline check failed", err)
}

return nil
}

// checkElf validates and detects zsh path.
func (c *Config) checkElf() error {
if c.Zshpath != "" && len(strings.TrimSpace(c.Zshpath)) > 0 {
if _, err := os.Stat(c.Zshpath); err != nil {
return fmt.Errorf("zsh path not found: %w", err)
}
c.ElfType = ElfTypeBin
return nil
}

if zsh, found := os.LookupEnv("SHELL"); found && strings.Contains(zsh, "zsh") {
c.Zshpath = zsh
c.ElfType = ElfTypeBin
return nil
}

if _, err := os.Stat(fallbackZshPath); err == nil {
c.Zshpath = fallbackZshPath
c.ElfType = ElfTypeBin
return nil
}

return fmt.Errorf("cannot find valid zsh path in $SHELL or %s", fallbackZshPath)
}

// checkReadlineFunc determines which zsh function to hook.
func (c *Config) checkReadlineFunc() error {
binaryPath := c.Zshpath
if binaryPath == "" {
binaryPath = fallbackZshPath
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

targetSymbol := "zleentry"
for _, sym := range symbols {
if sym.Name == targetSymbol {
c.ReadlineFuncName = targetSymbol
return nil
}
}

return fmt.Errorf("symbol [%s] not found in [%s]", targetSymbol, binaryPath)
}

// Bytes serializes the configuration to JSON.
func (c *Config) Bytes() []byte {
b, err := json.Marshal(c)
if err != nil {
return []byte{}
}
return b
}
