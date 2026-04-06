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
	"strings"

	pkgebpf "github.com/gojue/ecapture/pkg/util/ebpf"
)

/*
About CGroup path: must be a cgroup v2 (cgroup2) filesystem mount point or a subdirectory thereof.
On Ubuntu systems with cgroup v2, the default mount point is /sys/fs/cgroup.
On hybrid systems (cgroup v1 + v2), cgroup v2 may be at /sys/fs/cgroup/unified.

You can also create a custom cgroup v2 mount:

	mkdir /mnt/ecapture_cgroupv2
	mount -t cgroup2 none /mnt/ecapture_cgroupv2
*/

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

	// Try the historical default first.
	if ifaceHasAddr("wlan0") {
		c.Ifname = "wlan0"
		return
	}

	// Fallback: iterate all interfaces looking for one that is up and has an
	// address, skipping loopback.
	if name := firstUpNonLoopbackInterface(); name != "" {
		c.Ifname = name
		return
	}

	c.Ifname = "wlan0"
}

// validateCgroupPath validates and resolves the cgroup path on Linux.
// It checks that the configured cgroup path resides on a cgroup v2 filesystem.
func (c *Config) validateCgroupPath() error {
	if c.CGroupPath == "" {
		return nil
	}
	// Delegate to the shared cgroup validation in pkg/util/ebpf.
	_, err := pkgebpf.GetCgroupIdFromPath(c.CGroupPath)
	return err
}
