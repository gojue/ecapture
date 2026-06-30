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

// GetCgroupIdFromPath returns the cgroup ID for the given path.
// On Windows, cgroups are not supported. Returns 0 (no filtering).
func GetCgroupIdFromPath(_ string) (uint64, error) {
	// Cgroups are a Linux-only feature. On Windows, process filtering
	// is done via PID/ProcessName instead.
	return 0, nil
}
