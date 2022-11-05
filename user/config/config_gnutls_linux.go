//go:build !androidgki
// +build !androidgki

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
	"path/filepath"
	"strings"

	"errors"
)

func (this *GnutlsConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Gnutls != "" || len(strings.TrimSpace(this.Gnutls)) > 0 {
		_, e := os.Stat(this.Gnutls)
		if e != nil {
			return e
		}
		this.ElfType = ELF_TYPE_SO
		return nil
	}

	if this.NoSearch {
		return errors.New("NoSearch requires specifying lib path")
	}

	//如果配置 Curlpath的地址，判断文件是否存在，不存在则直接返回
	if this.Curlpath != "" || len(strings.TrimSpace(this.Curlpath)) > 0 {
		_, e := os.Stat(this.Curlpath)
		if e != nil {
			return e
		}
	} else {
		//如果没配置，则直接指定。
		this.Curlpath = "/usr/bin/wget"
	}

	soPath, e := getDynPathByElf(this.Curlpath, "libgnutls.so")
	if e != nil {
		//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		_, e = os.Stat(X86_BINARY_PREFIX)
		prefix := X86_BINARY_PREFIX
		if e != nil {
			prefix = OTHERS_BINARY_PREFIX
		}
		this.Gnutls = filepath.Join(prefix, "libgnutls.so.30")
		this.ElfType = ELF_TYPE_SO
		_, e = os.Stat(this.Gnutls)
		if e != nil {
			return e
		}
		return nil
	}

	this.Gnutls = soPath
	this.ElfType = ELF_TYPE_SO

	return nil
}
