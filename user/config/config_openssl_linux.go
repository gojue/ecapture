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
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	DEFAULT_IFNAME = "eth0"
)

func (this *OpensslConfig) checkOpenssl() error {
	soPath, e := getDynPathByElf(this.Curlpath, "libssl.so")
	if e != nil {
		//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		_, e = os.Stat(X86_BINARY_PREFIX)
		prefix := X86_BINARY_PREFIX
		if e != nil {
			prefix = OTHERS_BINARY_PREFIX
		}

		//	ubuntu 21.04	libssl.so.1.1   default
		this.Openssl = filepath.Join(prefix, "libssl.so.1.1")
		this.ElfType = ELF_TYPE_SO
		_, e = os.Stat(this.Openssl)
		if e != nil {
			return e
		}
	} else {
		this.Openssl = soPath
		this.ElfType = ELF_TYPE_SO
	}
	return nil
}

func (this *OpensslConfig) Check() error {
	this.IsAndroid = false
	var checkedOpenssl bool
	// 如果readline 配置，且存在，则直接返回。
	if this.Openssl != "" || len(strings.TrimSpace(this.Openssl)) > 0 {
		_, e := os.Stat(this.Openssl)
		if e != nil {
			return e
		}
		this.ElfType = ELF_TYPE_SO
		checkedOpenssl = true
	}

	//如果配置 Curlpath的地址，判断文件是否存在，不存在则直接返回
	if this.Curlpath != "" || len(strings.TrimSpace(this.Curlpath)) > 0 {
		_, e := os.Stat(this.Curlpath)
		if e != nil {
			return e
		}
	} else {
		//如果没配置，则直接指定。
		this.Curlpath = "/usr/bin/curl"
	}

	if this.Ifname == "" || len(strings.TrimSpace(this.Ifname)) == 0 {
		this.Ifname = DEFAULT_IFNAME
	}

	if checkedOpenssl {
		return nil
	}

	if this.NoSearch {
		return errors.New("NoSearch requires specifying lib path")
	}

	if !checkedOpenssl {
		e := this.checkOpenssl()
		if e != nil {
			return e
		}
	}

	return nil
}
