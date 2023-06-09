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

const DefaultGnutlsPath = "/apex/com.android.conscrypt/lib64/libgnutls"

func (gc *GnutlsConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if gc.Gnutls != "" || len(strings.TrimSpace(gc.Gnutls)) > 0 {
		_, e := os.Stat(gc.Gnutls)
		if e != nil {
			return e
		}
		gc.ElfType = ElfTypeSo
		return nil
	}

	gc.Gnutls = DefaultGnutlsPath
	gc.ElfType = ElfTypeSo

	return nil
}
