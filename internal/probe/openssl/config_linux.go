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

package openssl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

/*
About CGroup path: can be created manually or use the system default. Not limited to CGroup version, v1 and v2 are both supported.
On Ubuntu systems, the default is /sys/fs/cgroup. On CentOS, you can create your own.
Commands:
  mkdir /mnt/ecapture_cgroupv2
  mount -t cgroup2 none /mnt/ecapture_cgroupv2
*/
const (
	cgroupPath       = "/sys/fs/cgroup"         // default (ubuntu)
	cgroupPathCentos = "/mnt/ecapture_cgroupv2" // centos
)

// Linux-specific version of detectOpenSSL
func (c *Config) detectOpenSSL() error {
	// If OpenSSL path is configured, validate it
	if c.OpensslPath != "" {
		if _, err := os.Stat(c.OpensslPath); err != nil {
			return fmt.Errorf("openssl path not found: %w", err)
		}
		return nil
	}

	// Try common library paths
	commonPaths := []string{
		// Standard Linux OpenSSL paths
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
		"/usr/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/aarch64-linux-gnu/libssl.so.1.1",
		"/lib/aarch64-linux-gnu/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib/libssl.so.1.1",
		"/usr/lib/libssl.so.3",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			c.OpensslPath = path
			return nil
		}
	}

	// Try to find libssl.so via ldconfig or locate
	return fmt.Errorf("cannot find libssl.so in common paths")
}

// Linux-specific version of detectOS
func (c *Config) detectOS() error {
	if c.OpensslPath == "" {
		return fmt.Errorf("openssl path not set")
	}

	// set Android-specific flags
	c.IsAndroid = false

	// Check if it's BoringSSL (path-based detection)
	if strings.Contains(c.OpensslPath, "boringssl") {
		c.IsBoringSSL = true
		return nil
	}

	// Detect OpenSSL version from ELF
	// This is a simplified version - production code would use proper ELF parsing
	c.IsBoringSSL = false

	return nil
}

// Linux-specific default interface (no-op)
func (c *Config) setDefaultIfname() {
	// Linux doesn't need a default interface
	if c.Ifname != "" {
		return
	}

	c.Ifname = "wlan0"
}

// validateCgroupPath validates and resolves the cgroup path on Linux.
// It checks if the configured cgroup path is a cgroup v2 filesystem,
// tries fallback paths, and optionally creates/mounts cgroup v2 if needed.
func (c *Config) validateCgroupPath() error {
	if c.CGroupPath == "" {
		// No cgroup path configured, skip validation
		return nil
	}

	resolvedPath, err := checkCgroupPath(c.CGroupPath)
	if err != nil {
		return err
	}
	c.CGroupPath = resolvedPath
	return nil
}

// checkCgroupPath validates the given cgroup path and returns a resolved path.
// It checks if the path is a cgroup v2 filesystem, tries fallback paths,
// and creates/mounts cgroup v2 if necessary.
func checkCgroupPath(cp string) (string, error) {
	var st syscall.Statfs_t
	err := syscall.Statfs(cp, &st)
	if err != nil {
		return "", err
	}
	newPath := cp
	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		// On hybrid cgroup systems (cgroup v1 + v2), cgroup v2 is typically
		// mounted at /sys/fs/cgroup/unified while v1 controllers are at /sys/fs/cgroup
		newPath = filepath.Join(cgroupPath, "unified")
	}

	// Check if the path exists and is a valid cgroup v2
	err = syscall.Statfs(newPath, &st)
	if err == nil {
		return newPath, nil
	}

	// Try CentOS fallback path
	newPath = cgroupPathCentos
	err = syscall.Statfs(newPath, &st)
	if err == nil {
		return newPath, nil
	}

	// Create and mount cgroup v2 at the fallback path
	if err = os.MkdirAll(newPath, os.FileMode(0o755)); err != nil {
		return "", err
	}
	err = syscall.Mount("none", newPath, "cgroup2", 0, "")
	if err != nil {
		return "", err
	}
	return newPath, nil
}
