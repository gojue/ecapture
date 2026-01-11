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

package nspr

import (
	"testing"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatal("NewConfig() returned nil")
		return
	}

	if cfg.Pid != 0 {
		t.Errorf("Expected default Pid 0, got %d", cfg.Pid)
		return
	}

	if cfg.BaseConfig == nil {
		t.Error("BaseConfig should not be nil")
	}
}

func TestConfig_isSupportedVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{"NSS 3.90", "3.90", true},
		{"NSS 3.88.1", "3.88.1", true},
		{"NSS 3.6", "3.6", true},
		{"NSS 2.0", "2.0", false},
		{"NSS 4.0", "4.0", false},
	}

	cfg := NewConfig()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.isSupportedVersion(tt.version)
			if result != tt.expected {
				t.Errorf("isSupportedVersion(%s) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestConfig_selectBPFFileName(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"NSS 3.90", "3.90", "nspr_kern.o"},
		{"NSS 3.88", "3.88", "nspr_kern.o"},
		{"NSS 3.6", "3.6", "nspr_kern.o"},
	}

	cfg := NewConfig()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.selectBPFFileName(tt.version)
			if result != tt.expected {
				t.Errorf("selectBPFFileName(%s) = %s, want %s", tt.version, result, tt.expected)
			}
		})
	}
}
