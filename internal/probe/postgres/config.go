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

package postgres

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

// Config extends BaseConfig with PostgreSQL-specific configuration
type Config struct {
	*config.BaseConfig
	PostgresPath string // Path to PostgreSQL binary
	FuncName     string // Function name to hook (default: exec_simple_query)
	Offset       uint64 // Function offset (optional, auto-discovered if not set)
}

// NewConfig creates a new PostgreSQL probe configuration
func NewConfig() *Config {
	return &Config{
		BaseConfig: config.NewBaseConfig(),
		FuncName:   "exec_simple_query", // Default function to hook
	}
}

// Validate validates the PostgreSQL configuration
func (c *Config) Validate() error {
	// Validate base configuration
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.Wrap(errors.ErrCodeConfigValidation, "base config validation failed", err)
	}

	// Validate PostgreSQL path
	if c.PostgresPath == "" || len(strings.TrimSpace(c.PostgresPath)) == 0 {
		// Try to auto-detect PostgreSQL binary
		if err := c.detectPostgresPath(); err != nil {
			return errors.New(errors.ErrCodeConfiguration, "PostgreSQL path not set and auto-detection failed").
				WithContext("error", err.Error())
		}
	}

	// Verify PostgreSQL binary exists
	if _, err := os.Stat(c.PostgresPath); err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "PostgreSQL binary not found", err).
			WithContext("path", c.PostgresPath)
	}

	// Validate function name
	if c.FuncName == "" {
		c.FuncName = "exec_simple_query"
	}

	// Verify function exists in binary
	if err := c.verifyFunction(); err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "function verification failed", err).
			WithContext("function", c.FuncName)
	}

	return nil
}

// detectPostgresPath attempts to auto-detect the PostgreSQL binary path
func (c *Config) detectPostgresPath() error {
	// Common PostgreSQL binary locations
	commonPaths := []string{
		"/usr/lib/postgresql/15/bin/postgres",
		"/usr/lib/postgresql/14/bin/postgres",
		"/usr/lib/postgresql/13/bin/postgres",
		"/usr/lib/postgresql/12/bin/postgres",
		"/usr/lib/postgresql/11/bin/postgres",
		"/usr/pgsql-15/bin/postgres",
		"/usr/pgsql-14/bin/postgres",
		"/usr/pgsql-13/bin/postgres",
		"/usr/pgsql-12/bin/postgres",
		"/usr/local/pgsql/bin/postgres",
		"/opt/postgresql/bin/postgres",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			c.PostgresPath = path
			return nil
		}
	}

	return fmt.Errorf("could not find PostgreSQL binary in common locations")
}

// verifyFunction verifies that the function exists in the PostgreSQL binary
func (c *Config) verifyFunction() error {
	// Open the ELF file
	elfFile, err := elf.Open(c.PostgresPath)
	if err != nil {
		return fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer elfFile.Close()

	// Get symbols
	symbols, err := elfFile.Symbols()
	if err != nil {
		// Try dynamic symbols
		symbols, err = elfFile.DynamicSymbols()
		if err != nil {
			return fmt.Errorf("failed to read symbols: %w", err)
		}
	}

	// Search for the function
	found := false
	for _, sym := range symbols {
		if sym.Name == c.FuncName {
			found = true
			// Store offset if not already set
			if c.Offset == 0 {
				c.Offset = sym.Value
			}
			break
		}
	}

	if !found {
		return fmt.Errorf("function '%s' not found in PostgreSQL binary", c.FuncName)
	}

	return nil
}

// GetPostgresPath returns the PostgreSQL binary path
func (c *Config) GetPostgresPath() string {
	return c.PostgresPath
}

// GetFuncName returns the function name to hook
func (c *Config) GetFuncName() string {
	return c.FuncName
}

// GetOffset returns the function offset
func (c *Config) GetOffset() uint64 {
	return c.Offset
}

// SetPostgresPath sets the PostgreSQL binary path
func (c *Config) SetPostgresPath(path string) {
	c.PostgresPath = path
}

// SetFuncName sets the function name to hook
func (c *Config) SetFuncName(name string) {
	c.FuncName = name
}

// SetOffset sets the function offset
func (c *Config) SetOffset(offset uint64) {
	c.Offset = offset
}
