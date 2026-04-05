//go:build !ecap_android
// +build !ecap_android

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

package ebpf

import (
	"testing"
)

func TestGetCgroupIdFromPath_Empty(t *testing.T) {
	id, err := GetCgroupIdFromPath("")
	if err != nil {
		t.Errorf("GetCgroupIdFromPath('') should not fail, got: %v", err)
	}
	if id != 0 {
		t.Errorf("GetCgroupIdFromPath('') should return 0, got: %d", id)
	}
}

func TestGetCgroupIdFromPath_DefaultCgroup(t *testing.T) {
	// /sys/fs/cgroup should exist on most Linux systems with cgroup v2
	id, err := GetCgroupIdFromPath("/sys/fs/cgroup")
	if err != nil {
		t.Logf("GetCgroupIdFromPath('/sys/fs/cgroup') failed (may be expected on some systems): %v", err)
		return
	}
	if id == 0 {
		t.Error("GetCgroupIdFromPath('/sys/fs/cgroup') returned 0, expected non-zero cgroup id")
	}
	t.Logf("Cgroup ID for /sys/fs/cgroup: %d", id)
}

func TestGetCgroupIdFromPath_InvalidPath(t *testing.T) {
	_, err := GetCgroupIdFromPath("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("GetCgroupIdFromPath() should fail for non-existent path")
	}
}
