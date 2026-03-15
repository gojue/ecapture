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

package mysql

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
)

// MysqlVersion represents the MySQL/MariaDB server version
type MysqlVersion uint8

const (
	MysqlVersionUnknown MysqlVersion = iota
	MysqlVersion56
	MysqlVersion57
	MysqlVersion80
)

// String returns the string representation of the MySQL version
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

// Config holds the MySQL probe configuration
type Config struct {
	*config.BaseConfig

	// MySQL server binary path
	MysqlPath string

	// Function name to hook (dispatch_command variant)
	FuncName string

	// Function offset (if using offset instead of function name)
	Offset uint64

	// MySQL version detected
	Version MysqlVersion

	// Version string (e.g., "mysqld-5.7.35")
	VersionInfo string
}

// NewConfig creates a new MySQL probe configuration
func NewConfig() *Config {
	return &Config{
		BaseConfig:  config.NewBaseConfig(),
		Version:     MysqlVersionUnknown,
		VersionInfo: "",
	}
}

// Validate validates the MySQL probe configuration
func (c *Config) Validate() error {
	// Validate base configuration
	if err := c.BaseConfig.Validate(); err != nil {
		return err
	}

	// Check if MySQL path is provided, if not, try to detect from PID
	if c.MysqlPath == "" || len(strings.TrimSpace(c.MysqlPath)) == 0 {
		// If PID is provided, try to detect binary path from it
		if c.GetPid() > 0 {
			if detectedPath, err := c.detectBinaryPathFromPid(c.GetPid()); err == nil && detectedPath != "" {
				c.MysqlPath = detectedPath
			}
		}

		// If still empty after detection attempt, return error
		if c.MysqlPath == "" || len(strings.TrimSpace(c.MysqlPath)) == 0 {
			return errors.NewConfigurationError(
				"MySQL path cannot be empty and cannot be auto-detected",
				fmt.Errorf("empty mysql path and no PID provided for auto-detection"),
			).WithContext("path", c.MysqlPath).WithContext("pid", fmt.Sprintf("%d", c.GetPid()))
		}
	}

	// Check if MySQL binary exists
	if _, err := os.Stat(c.MysqlPath); err != nil {
		if os.IsNotExist(err) {
			return errors.NewConfigurationError(
				"MySQL binary not found",
				err,
			).WithContext("path", c.MysqlPath)
		}
		return errors.NewConfigurationError(
			"Failed to stat MySQL binary",
			err,
		).WithContext("path", c.MysqlPath)
	}

	// If function name is provided, use it directly
	if c.FuncName != "" && len(strings.TrimSpace(c.FuncName)) > 0 {
		return nil
	}

	// If offset is provided, use offset instead
	if c.Offset > 0 {
		c.FuncName = "[_IGNORE_]"
		return nil
	}

	// Auto-detect function name and version
	if err := c.detectFunctionAndVersion(); err != nil {
		return err
	}

	return nil
}

// detectFunctionAndVersion automatically detects the dispatch_command function
// and MySQL version from the binary
func (c *Config) detectFunctionAndVersion() error {
	// Open the ELF file
	elfFile, err := elf.Open(c.MysqlPath)
	if err != nil {
		return errors.NewConfigurationError(
			"Failed to open MySQL binary as ELF",
			err,
		).WithContext("path", c.MysqlPath)
	}
	defer func() {
		_ = elfFile.Close()
	}()

	// Read dynamic symbols
	dynamicSymbols, err := elfFile.DynamicSymbols()
	if err != nil {
		return errors.NewConfigurationError(
			"Failed to read dynamic symbols",
			err,
		).WithContext("path", c.MysqlPath)
	}

	// Look for dispatch_command function
	// Pattern: _Z16dispatch_command19enum_server_commandP3THDPcjbb (example)
	funcPattern := regexp.MustCompile(`\w+dispatch_command\w+`)
	var funcName string

	for _, sym := range dynamicSymbols {
		if match := funcPattern.FindStringSubmatch(sym.Name); match != nil {
			funcName = sym.Name
			break
		}
	}

	if funcName == "" {
		return errors.NewConfigurationError(
			"Cannot find dispatch_command function in MySQL binary",
			fmt.Errorf("no matching function found"),
		).WithContext("path", c.MysqlPath)
	}

	c.FuncName = funcName

	// Default to MySQL 5.6
	c.Version = MysqlVersion56
	c.VersionInfo = "mysqld-5.6"

	// Check if it's MySQL 5.7 or 8.0 by looking for COM_DATA in function name
	if strings.Contains(funcName, "COM_DATA") {
		// Read .rodata section to detect exact version
		if rodataSection := elfFile.Section(".rodata"); rodataSection != nil {
			if rodataData, err := rodataSection.Data(); err == nil {
				version, versionInfo := c.detectMysqlVersion(rodataData)
				c.Version = version
				c.VersionInfo = versionInfo
			}
		}
	}

	return nil
}

// detectMysqlVersion detects the exact MySQL version from .rodata section
func (c *Config) detectMysqlVersion(rodataData []byte) (MysqlVersion, string) {
	// Split by null bytes
	parts := bytes.Split(rodataData, []byte("\x00"))

	for _, part := range parts {
		if len(part) == 0 {
			continue
		}

		// Version string should be between 8 and 15 characters
		if len(part) > 15 || len(part) < 8 {
			continue
		}

		versionStr := string(part)

		// Check for MySQL 8.0
		if strings.Contains(versionStr, "mysqld-8.") {
			return MysqlVersion80, versionStr
		}

		// Check for MySQL 5.7
		if strings.Contains(versionStr, "mysqld-5.7") {
			return MysqlVersion57, versionStr
		}
	}

	return MysqlVersionUnknown, ""
}

// detectBinaryPathFromPid attempts to detect the MySQL binary path from a process ID
func (c *Config) detectBinaryPathFromPid(pid uint64) (string, error) {
	// Read the /proc/<pid>/exe symlink to get the binary path
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	binaryPath, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to read exe symlink for PID %d: %w", pid, err)
	}

	// Verify it's a MySQL/MariaDB binary by checking the name
	baseName := strings.ToLower(binaryPath)
	if !strings.Contains(baseName, "mysqld") && !strings.Contains(baseName, "mariadbd") {
		return "", fmt.Errorf("PID %d does not appear to be a MySQL/MariaDB process (binary: %s)", pid, binaryPath)
	}

	return binaryPath, nil
}

// GetFuncName returns the function name to hook
func (c *Config) GetFuncName() string {
	return c.FuncName
}

// GetOffset returns the function offset
func (c *Config) GetOffset() uint64 {
	return c.Offset
}

// GetVersion returns the detected MySQL version
func (c *Config) GetVersion() MysqlVersion {
	return c.Version
}

// GetVersionInfo returns the version information string
func (c *Config) GetVersionInfo() string {
	return c.VersionInfo
}

// GetBinaryPath returns the MySQL binary path
func (c *Config) GetBinaryPath() string {
	return c.MysqlPath
}

// String returns a string representation of the configuration
func (c *Config) String() string {
	return fmt.Sprintf("MySQL Config(path=%s, func=%s, version=%s, versionInfo=%s, offset=%d)",
		c.MysqlPath, c.FuncName, c.Version.String(), c.VersionInfo, c.Offset)
}
