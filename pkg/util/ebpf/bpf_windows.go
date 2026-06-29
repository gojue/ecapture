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

package ebpf

import "github.com/gojue/ecapture/internal/errors"

// GetHostKernelConfig returns the kernel configuration for the current host.
// On Windows, eBPF kernel config is not applicable.
func GetHostKernelConfig() (map[string]bool, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "eBPF kernel config is not available on Windows")
}

// CheckKernelConfig checks if a specific kernel configuration option is enabled.
// On Windows, this always returns false as eBPF is not supported.
func CheckKernelConfig(option string) bool {
	return false
}
