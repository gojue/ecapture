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
	"os"
	"strings"
)

const (
	DefaultOpensslPath = "/apex/com.android.conscrypt/lib64/libssl.so"
	//DEFAULT_LIBC_PATH    = "/apex/com.android.runtime/lib64/bionic/libc.so"

	DefaultIfname = "wlan0"
)

func (this *OpensslConfig) Check() error {
	this.IsAndroid = true
	// 如果readline 配置，且存在，则直接返回。
	if this.Openssl != "" || len(strings.TrimSpace(this.Openssl)) > 0 {
		_, e := os.Stat(this.Openssl)
		if e != nil {
			return e
		}
		this.ElfType = ElfTypeSo
	} else {
		this.ElfType = ElfTypeSo
		this.Openssl = DefaultOpensslPath
	}

	if this.Ifname == "" || len(strings.TrimSpace(this.Ifname)) == 0 {
		this.Ifname = DefaultIfname
	}
	return nil
}
