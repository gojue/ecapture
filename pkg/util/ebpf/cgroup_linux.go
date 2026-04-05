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
	"encoding/binary"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// GetCgroupIdFromPath returns the cgroup ID for the given cgroup v2 path.
// The cgroup ID is obtained via the file handle of the cgroup directory,
// which matches the value returned by bpf_get_current_cgroup_id() in eBPF programs.
// Returns 0 if cgroupPath is empty.
func GetCgroupIdFromPath(cgroupPath string) (uint64, error) {
	if cgroupPath == "" {
		return 0, nil
	}

	// Validate that the path is on a cgroup v2 filesystem before resolving.
	var st syscall.Statfs_t
	if err := syscall.Statfs(cgroupPath, &st); err != nil {
		return 0, fmt.Errorf("failed to stat cgroup path %q: %w", cgroupPath, err)
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return 0, fmt.Errorf("path %q is not on a cgroup v2 filesystem (type=0x%x, want cgroup2=0x%x); "+
			"please specify a path on a cgroup v2 mount (e.g., /sys/fs/cgroup on pure cgroup v2 systems, "+
			"or /sys/fs/cgroup/unified on hybrid systems)",
			cgroupPath, st.Type, unix.CGROUP2_SUPER_MAGIC)
	}

	fh, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to get cgroup id from path %s: %w", cgroupPath, err)
	}

	if fh.Size() != 8 {
		return 0, fmt.Errorf("unexpected file handle size %d for cgroup path %s, expected 8-byte cgroup ID", fh.Size(), cgroupPath)
	}

	cgroupID := binary.LittleEndian.Uint64(fh.Bytes())
	return cgroupID, nil
}
