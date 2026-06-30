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

package kernel

import (
	"golang.org/x/sys/windows"
)

// HostVersionIn is the host kernel version function for Windows.
// Returns a pseudo version number based on Windows build number for compatibility.
func HostVersionIn() (uint32, error) {
	ver := windows.RtlGetVersion()
	if ver == nil {
		return 0, ErrNonLinux
	}
	// Map Windows build number to a pseudo kernel version for compatibility
	// Windows 10 build 17763 -> pseudo version 10.177.63
	// This is used only for compatibility checks, not actual kernel version comparison
	return uint32(ver.BuildNumber), nil
}
