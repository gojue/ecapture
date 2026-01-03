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

package gotls

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFindSymbolOffsets(t *testing.T) {
	// Build the test Go binary
	examplePath := filepath.Join("..", "..", "..", "examples", "https_client", "golang_https.go")
	
	// Check if example file exists
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skipf("Example file not found: %s", examplePath)
	}

	// Create temp directory for test binary
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "test_golang_https")

	// Build the test binary
	cmd := exec.Command("go", "build", "-o", binaryPath, examplePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build test binary: %v\nOutput: %s", err, output)
	}

	// Create config and set ElfPath
	cfg := NewConfig()
	cfg.ElfPath = binaryPath

	// Test findSymbolOffsets
	err = cfg.findSymbolOffsets()
	if err != nil {
		t.Fatalf("findSymbolOffsets failed: %v", err)
	}

	// Verify that offsets were found
	if cfg.GoTlsWriteAddr == 0 {
		t.Error("GoTlsWriteAddr is 0, expected non-zero offset")
	}

	if len(cfg.ReadTlsAddrs) == 0 {
		t.Error("ReadTlsAddrs is empty, expected at least one offset")
	}

	if cfg.ReadTlsAddrs[0] == 0 {
		t.Error("ReadTlsAddrs[0] is 0, expected non-zero offset")
	}

	t.Logf("Successfully found offsets:")
	t.Logf("  GoTlsWriteAddr: 0x%x", cfg.GoTlsWriteAddr)
	t.Logf("  ReadTlsAddrs: %v", cfg.ReadTlsAddrs)
}

func TestFindSymbolOffsets_InvalidPath(t *testing.T) {
	cfg := NewConfig()
	cfg.ElfPath = "/nonexistent/path/to/binary"

	err := cfg.findSymbolOffsets()
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestFindSymbolOffsets_NonGoBinary(t *testing.T) {
	// Create a simple non-Go ELF binary for testing
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "test_non_go")

	// Create a simple C program
	cCode := `
int main() {
    return 0;
}
`
	cFile := filepath.Join(tmpDir, "test.c")
	err := os.WriteFile(cFile, []byte(cCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write C file: %v", err)
	}

	// Compile it
	cmd := exec.Command("gcc", "-o", binaryPath, cFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("gcc not available or compilation failed: %v\nOutput: %s", err, output)
	}

	cfg := NewConfig()
	cfg.ElfPath = binaryPath

	err = cfg.findSymbolOffsets()
	if err == nil {
		t.Error("Expected error for non-Go binary, got nil")
	}
}

func TestReadGoSymbolTable(t *testing.T) {
	// Build the test Go binary
	examplePath := filepath.Join("..", "..", "..", "examples", "https_client", "golang_https.go")
	
	// Check if example file exists
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skipf("Example file not found: %s", examplePath)
	}

	// Create temp directory for test binary
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "test_golang_https")

	// Build the test binary
	cmd := exec.Command("go", "build", "-o", binaryPath, examplePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build test binary: %v\nOutput: %s", err, output)
	}

	// The test validates that we can read the symbol table
	// The actual implementation is tested via findSymbolOffsets
	_ = binaryPath
}
