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

package errors

import (
	"errors"
	"testing"
)

func TestNew(t *testing.T) {
	err := New(ErrCodeConfiguration, "test error")
	if err.Code != ErrCodeConfiguration {
		t.Errorf("expected code %d, got %d", ErrCodeConfiguration, err.Code)
		return
	}
	if err.Message != "test error" {
		t.Errorf("expected message 'test error', got '%s'", err.Message)
		return
	}
}

func TestWrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := Wrap(ErrCodeProbeInit, "probe init failed", cause)

	if err.Code != ErrCodeProbeInit {
		t.Errorf("expected code %d, got %d", ErrCodeProbeInit, err.Code)
		return
	}
	if !errors.Is(err, cause) {
		t.Error("expected cause to be set")
	}
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find cause")
	}
}

func TestWithContext(t *testing.T) {
	err := New(ErrCodeConfiguration, "test error").
		WithContext("pid", 1234).
		WithContext("probe", "openssl")

	if err.Context["pid"] != 1234 {
		t.Errorf("expected pid context to be 1234, got %v", err.Context["pid"])
		return
	}
	if err.Context["probe"] != "openssl" {
		t.Errorf("expected probe context to be 'openssl', got %v", err.Context["probe"])
		return
	}
}

func TestNewProbeStartError(t *testing.T) {
	cause := errors.New("failed to attach")
	err := NewProbeStartError("openssl", cause)

	if err.Code != ErrCodeProbeStart {
		t.Errorf("expected code %d, got %d", ErrCodeProbeStart, err.Code)
		return
	}
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find cause")
	}
}

func TestErrorString(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name:     "simple error",
			err:      New(ErrCodeConfiguration, "config error"),
			expected: "[101] config error",
		},
		{
			name:     "wrapped error",
			err:      Wrap(ErrCodeProbeInit, "init failed", errors.New("underlying")),
			expected: "[201] init failed: underlying",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, tt.err.Error())
			}
		})
	}
}
