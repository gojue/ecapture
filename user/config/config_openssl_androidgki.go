//go:build androidgki
// +build androidgki

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

package config

import (
	"bufio"
	"os"
	"strings"
)

const (
	DefaultOpensslPath = "/apex/com.android.conscrypt/lib64/libssl.so"
	DefaultLibcPath    = "/apex/com.android.runtime/lib64/bionic/libc.so"
	BuildPropPath      = "/system/build.prop"
	ReleasePrefix      = "ro.build.version.release="
	DefaultIfname      = "wlan0"
)

func (oc *OpensslConfig) Check() error {
	oc.AndroidVer = "12"
	oc.IsAndroid = true
	// 如果readline 配置，且存在，则直接返回。
	if oc.Openssl != "" || len(strings.TrimSpace(oc.Openssl)) > 0 {
		_, e := os.Stat(oc.Openssl)
		if e != nil {
			return e
		}
		oc.ElfType = ElfTypeSo
	} else {
		oc.ElfType = ElfTypeSo
		oc.Openssl = DefaultOpensslPath
	}

	if oc.Ifname == "" || len(strings.TrimSpace(oc.Ifname)) == 0 {
		oc.Ifname = DefaultIfname
	}

	f, err := os.Open(BuildPropPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	//  detect android version (use Android version?), and set AndroidVer
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, ReleasePrefix) {
			oc.AndroidVer = strings.TrimSpace(strings.TrimPrefix(line, ReleasePrefix))
			break
		}
	}

	oc.Model = oc.checkModel()
	return nil
}
