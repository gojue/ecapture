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

package mysql

import (
	"fmt"
	"os"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

// MysqlVersion represents the MySQL/MariaDB server version.
type MysqlVersion uint8

const (
	MysqlVersionUnknown MysqlVersion = iota
	MysqlVersion56
	MysqlVersion57
	MysqlVersion80
)

// String returns the string representation of the MySQL version.
func (v MysqlVersion) String() string {
	switch v {
	case MysqlVersion56:
		return "MySQL 5.6"
	case MysqlVersion57:
		return "MySQL 5.7"
	case MysqlVersion80:
		return "MySQL 8.0"
	default:
		return "Unknown"
	}
}

// Config holds the MySQL probe configuration for Windows.
type Config struct {
	*config.BaseConfig

	// MysqlPath is the path to the MySQL client/server DLL or EXE.
	MysqlPath string

	// FuncName is the function name to hook. Supported: mysql_real_query,
	// mysql_query, dispatch_command.
	FuncName string

	// Offset is the optional function offset inside the binary.
	Offset uint64

	// Version is the detected MySQL version.
	Version MysqlVersion

	// VersionInfo is a human-readable version string.
	VersionInfo string
}

// NewConfig creates a new MySQL probe configuration for Windows.
func NewConfig() *Config {
	return &Config{
		BaseConfig:  config.NewBaseConfig(),
		FuncName:    "mysql_real_query",
		Version:     MysqlVersionUnknown,
		VersionInfo: "",
	}
}

// Validate validates the MySQL probe configuration on Windows.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.Wrap(errors.ErrCodeConfigValidation, "base config validation failed", err)
	}

	if c.MysqlPath == "" || strings.TrimSpace(c.MysqlPath) == "" {
		if err := c.detectMysqlPath(); err != nil {
			return errors.New(errors.ErrCodeConfiguration, "MySQL path not set and auto-detection failed").
				WithContext("error", err.Error())
		}
	}

	if _, err := os.Stat(c.MysqlPath); err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "MySQL binary not found", err).
			WithContext("path", c.MysqlPath)
	}

	if c.FuncName == "" {
		c.FuncName = "mysql_real_query"
	}

	c.VersionInfo = detectMysqlVersionInfo(c.MysqlPath)
	c.Version = parseMysqlVersion(c.VersionInfo)

	return nil
}

// detectMysqlPath attempts to locate a MySQL client DLL on Windows.
func (c *Config) detectMysqlPath() error {
	commonPaths := []string{
		`C:\Program Files\MySQL\MySQL Server 8.0\bin\libmysql.dll`,
		`C:\Program Files\MySQL\MySQL Server 5.7\bin\libmysql.dll`,
		`C:\Program Files (x86)\MySQL\MySQL Server 5.7\bin\libmysql.dll`,
		`C:\Program Files\MariaDB\MariaDB 10.6\bin\libmariadb.dll`,
		`C:\Program Files\MariaDB\MariaDB 10.5\bin\libmariadb.dll`,
		`C:\Program Files\MariaDB\MariaDB 10.4\bin\libmariadb.dll`,
		`C:\Windows\System32\libmysql.dll`,
		`C:\Windows\SysWOW64\libmysql.dll`,
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			c.MysqlPath = path
			return nil
		}
	}

	return errors.New(errors.ErrCodeConfiguration, "could not find MySQL/MariaDB DLL in common Windows locations")
}

// detectMysqlVersionInfo reads version strings from the binary file.
func detectMysqlVersionInfo(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	patterns := []string{
		"mysqld-8.",
		"mysqld-5.7",
		"mysqld-5.6",
		"libmysql-8.",
		"libmysql-5.7",
		"libmysql-5.6",
		"mariadbd-10.",
		"libmariadb-10.",
	}
	for _, pattern := range patterns {
		if idx := strings.Index(string(data), pattern); idx >= 0 {
			end := idx + len(pattern)
			for end < len(data) && isVersionChar(data[end]) {
				end++
			}
			return string(data[idx:end])
		}
	}
	return "unknown"
}

func isVersionChar(b byte) bool {
	return (b >= '0' && b <= '9') || b == '.' || b == '-'
}

// parseMysqlVersion maps a version string to a MysqlVersion.
func parseMysqlVersion(info string) MysqlVersion {
	if strings.Contains(info, "mysqld-8.") || strings.Contains(info, "libmysql-8.") {
		return MysqlVersion80
	}
	if strings.Contains(info, "mysqld-5.7") || strings.Contains(info, "libmysql-5.7") {
		return MysqlVersion57
	}
	if strings.Contains(info, "mysqld-5.6") || strings.Contains(info, "libmysql-5.6") {
		return MysqlVersion56
	}
	return MysqlVersionUnknown
}

// GetFuncName returns the function name to hook.
func (c *Config) GetFuncName() string { return c.FuncName }

// GetOffset returns the function offset.
func (c *Config) GetOffset() uint64 { return c.Offset }

// GetVersion returns the detected MySQL version.
func (c *Config) GetVersion() MysqlVersion { return c.Version }

// GetVersionInfo returns the version information string.
func (c *Config) GetVersionInfo() string { return c.VersionInfo }

// GetBinaryPath returns the MySQL binary path.
func (c *Config) GetBinaryPath() string { return c.MysqlPath }

// String returns a string representation of the configuration.
func (c *Config) String() string {
	return fmt.Sprintf("MySQL Config(path=%s, func=%s, version=%s, versionInfo=%s, offset=%d)",
		c.MysqlPath, c.FuncName, c.Version.String(), c.VersionInfo, c.Offset)
}

// GetKeylogFile returns the keylog file path (unused on Windows MySQL probe).
func (c *Config) GetKeylogFile() string { return "" }
