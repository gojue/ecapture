//go:build ecap_android
// +build ecap_android

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
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	// Android-specific default paths
	DefaultOpensslPath = "/apex/com.android.conscrypt/lib64/libssl.so"
	DefaultLibcPath    = "/apex/com.android.runtime/lib64/bionic/libc.so"
	BuildPropPath      = "/system/build.prop"
	ReleasePrefix      = "ro.build.version.release="
	DefaultIfname      = "wlan0"
)

// Android-specific version of detectOpenSSL
func (c *Config) detectOpenSSL() error {
	// If OpenSSL path is configured, validate it
	if c.OpensslPath != "" {
		if _, err := os.Stat(c.OpensslPath); err != nil {
			return fmt.Errorf("openssl path not found: %w", err)
		}
		return nil
	}

	// Android-specific paths for BoringSSL
	androidPaths := []string{
		"/apex/com.android.conscrypt/lib64/libssl.so",
		"/apex/com.android.conscrypt/lib/libssl.so",
		"/system/lib64/libssl.so",
		"/system/lib/libssl.so",
	}

	for _, path := range androidPaths {
		if _, err := os.Stat(path); err == nil {
			c.OpensslPath = path
			c.IsBoringSSL = true
			return nil
		}
	}

	return fmt.Errorf("cannot find libssl.so (BoringSSL) in Android paths")
}

// Android-specific version of detectVersion
func (c *Config) detectVersion() error {
	if c.OpensslPath == "" {
		return fmt.Errorf("openssl path not set")
	}

	// For Android, it's always BoringSSL
	c.IsBoringSSL = true

	// Detect Android version from build.prop
	androidVer, err := detectAndroidVersion()
	if err == nil && androidVer != "" {
		c.SslVersion = fmt.Sprintf("boringssl_android_%s", androidVer)
	} else {
		c.SslVersion = "boringssl"
	}

	return nil
}

// detectAndroidVersion reads the Android version from build.prop
func detectAndroidVersion() (string, error) {
	f, err := os.Open(BuildPropPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, ReleasePrefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, ReleasePrefix)), nil
		}
	}

	return "", fmt.Errorf("android version not found in build.prop")
}

// Android-specific default interface
func (c *Config) setDefaultIfname() {
	if c.Ifname == "" {
		c.Ifname = DefaultIfname
	}
}

