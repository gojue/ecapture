//go:build windows
// +build windows

package postgres

import (
	"strings"
	"testing"
)

func TestNewConfigDefaults(t *testing.T) {
	c := NewConfig()
	if c == nil {
		t.Fatal("NewConfig() returned nil")
	}
	if c.FuncName != "PQexec" {
		t.Errorf("default FuncName = %q, want PQexec", c.FuncName)
	}
}

func TestConfigValidateMissingBinary(t *testing.T) {
	c := NewConfig()
	c.PostgresPath = `C:\Nonexistent\libpq.dll`
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when binary path does not exist")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got %q", err.Error())
	}
}

func TestConfigGettersSetters(t *testing.T) {
	c := NewConfig()
	c.SetPostgresPath(`C:\test\libpq.dll`)
	c.SetFuncName("PQexecParams")
	c.SetOffset(0x5678)
	if c.GetPostgresPath() != `C:\test\libpq.dll` {
		t.Errorf("GetPostgresPath() = %q", c.GetPostgresPath())
	}
	if c.GetFuncName() != "PQexecParams" {
		t.Errorf("GetFuncName() = %q, want PQexecParams", c.GetFuncName())
	}
	if c.GetOffset() != 0x5678 {
		t.Errorf("GetOffset() = 0x%x, want 0x5678", c.GetOffset())
	}
}
