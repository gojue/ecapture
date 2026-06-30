//go:build windows
// +build windows

package mysql

import (
	"strings"
	"testing"
)

func TestNewConfigDefaults(t *testing.T) {
	c := NewConfig()
	if c == nil {
		t.Fatal("NewConfig() returned nil")
	}
	if c.FuncName != "mysql_real_query" {
		t.Errorf("default FuncName = %q, want mysql_real_query", c.FuncName)
	}
	if c.Version != MysqlVersionUnknown {
		t.Errorf("default Version = %v, want MysqlVersionUnknown", c.Version)
	}
}

func TestConfigValidateMissingBinary(t *testing.T) {
	c := NewConfig()
	c.MysqlPath = `C:\Nonexistent\libmysql.dll`
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when binary path does not exist")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got %q", err.Error())
	}
}

func TestConfigGetters(t *testing.T) {
	c := NewConfig()
	c.MysqlPath = `C:\test\libmysql.dll`
	c.FuncName = "mysql_query"
	c.Offset = 0x1234
	if c.GetBinaryPath() != c.MysqlPath {
		t.Errorf("GetBinaryPath() = %q, want %q", c.GetBinaryPath(), c.MysqlPath)
	}
	if c.GetFuncName() != "mysql_query" {
		t.Errorf("GetFuncName() = %q, want mysql_query", c.GetFuncName())
	}
	if c.GetOffset() != 0x1234 {
		t.Errorf("GetOffset() = 0x%x, want 0x1234", c.GetOffset())
	}
}
