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

package postgres

import (
	"os"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

// Config extends BaseConfig with PostgreSQL-specific configuration for Windows.
type Config struct {
	*config.BaseConfig

	// PostgresPath is the path to the PostgreSQL client DLL (libpq.dll) or EXE.
	PostgresPath string

	// FuncName is the function name to hook (default: PQexec).
	FuncName string

	// Offset is the optional function offset inside the binary.
	Offset uint64
}

// NewConfig creates a new PostgreSQL probe configuration for Windows.
func NewConfig() *Config {
	return &Config{
		BaseConfig:   config.NewBaseConfig(),
		FuncName:     "PQexec",
		PostgresPath: "",
	}
}

// Validate validates the PostgreSQL configuration on Windows.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.Wrap(errors.ErrCodeConfigValidation, "base config validation failed", err)
	}

	if c.PostgresPath == "" || strings.TrimSpace(c.PostgresPath) == "" {
		if err := c.detectPostgresPath(); err != nil {
			return errors.New(errors.ErrCodeConfiguration, "PostgreSQL path not set and auto-detection failed").
				WithContext("error", err.Error())
		}
	}

	if _, err := os.Stat(c.PostgresPath); err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "PostgreSQL binary not found", err).
			WithContext("path", c.PostgresPath)
	}

	if c.FuncName == "" {
		c.FuncName = "PQexec"
	}

	return nil
}

// detectPostgresPath attempts to locate libpq.dll on Windows.
func (c *Config) detectPostgresPath() error {
	commonPaths := []string{
		`C:\Program Files\PostgreSQL\15\bin\libpq.dll`,
		`C:\Program Files\PostgreSQL\14\bin\libpq.dll`,
		`C:\Program Files\PostgreSQL\13\bin\libpq.dll`,
		`C:\Program Files\PostgreSQL\12\bin\libpq.dll`,
		`C:\Program Files\PostgreSQL\11\bin\libpq.dll`,
		`C:\Program Files (x86)\PostgreSQL\15\bin\libpq.dll`,
		`C:\Program Files (x86)\PostgreSQL\14\bin\libpq.dll`,
		`C:\Windows\System32\libpq.dll`,
		`C:\Windows\SysWOW64\libpq.dll`,
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			c.PostgresPath = path
			return nil
		}
	}

	return errors.New(errors.ErrCodeConfiguration, "could not find libpq.dll in common Windows locations")
}

// GetPostgresPath returns the PostgreSQL binary path.
func (c *Config) GetPostgresPath() string { return c.PostgresPath }

// GetFuncName returns the function name to hook.
func (c *Config) GetFuncName() string { return c.FuncName }

// GetOffset returns the function offset.
func (c *Config) GetOffset() uint64 { return c.Offset }

// SetPostgresPath sets the PostgreSQL binary path.
func (c *Config) SetPostgresPath(path string) { c.PostgresPath = path }

// SetFuncName sets the function name to hook.
func (c *Config) SetFuncName(name string) { c.FuncName = name }

// SetOffset sets the function offset.
func (c *Config) SetOffset(offset uint64) { c.Offset = offset }

// GetKeylogFile returns the keylog file path (unused on Windows Postgres probe).
func (c *Config) GetKeylogFile() string { return "" }
