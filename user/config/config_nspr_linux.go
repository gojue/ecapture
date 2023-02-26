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

func (this *NsprConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Nsprpath != "" || len(strings.TrimSpace(this.Nsprpath)) > 0 {
		_, e := os.Stat(this.Nsprpath)
		if e != nil {
			return e
		}
		this.ElfType = ElfTypeSo
		return nil
	}

	if this.NoSearch {
		return errors.New("NoSearch requires specifying lib path")
	}

	//如果配置 Curlpath的地址，判断文件是否存在，不存在则直接返回
	if this.Firefoxpath != "" || len(strings.TrimSpace(this.Firefoxpath)) > 0 {
		_, e := os.Stat(this.Firefoxpath)
		if e != nil {
			return e
		}
	} else {
		//如果没配置，则直接指定。
		this.Firefoxpath = "/usr/lib/firefox/firefox"
	}

	soPath, e := getDynPathByElf(this.Firefoxpath, "libnspr4.so")
	if e != nil {
		//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		_, e = os.Stat(X86BinaryPrefix)
		prefix := X86BinaryPrefix
		if e != nil {
			prefix = OthersBinaryPrefix
		}
		this.Nsprpath = filepath.Join(prefix, "libnspr4.so")
		//this.Gnutls = "/usr/lib/firefox/libnss3.so"
		//"/usr/lib/firefox/libnspr4.so"
		this.ElfType = ElfTypeSo
		_, e = os.Stat(this.Nsprpath)
		if e != nil {
			return e
		}
		return nil
	}

	this.Nsprpath = soPath
	this.ElfType = ElfTypeSo

	return nil
}
