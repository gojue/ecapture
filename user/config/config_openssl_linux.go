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
	DefaultIfname = "eth0"
)

func (oc *OpensslConfig) checkOpenssl() error {
	soPath, e := getDynPathByElf(oc.Curlpath, "libssl.so")
	if e != nil {
		//oc.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		_, e = os.Stat(X86BinaryPrefix)
		prefix := X86BinaryPrefix
		if e != nil {
			prefix = OthersBinaryPrefix
		}

		//	ubuntu 21.04	libssl.so.1.1   default
		oc.Openssl = filepath.Join(prefix, "libssl.so.1.1")
		oc.ElfType = ElfTypeSo
		_, e = os.Stat(oc.Openssl)
		if e != nil {
			return e
		}
	} else {
		oc.Openssl = soPath
		oc.ElfType = ElfTypeSo
	}
	return nil
}

func (oc *OpensslConfig) Check() error {
	oc.IsAndroid = false
	var checkedOpenssl bool
	// 如果readline 配置，且存在，则直接返回。
	if oc.Openssl != "" || len(strings.TrimSpace(oc.Openssl)) > 0 {
		_, e := os.Stat(oc.Openssl)
		if e != nil {
			return e
		}
		oc.ElfType = ElfTypeSo
		checkedOpenssl = true
	}

	//如果配置 Curlpath的地址，判断文件是否存在，不存在则直接返回
	if oc.Curlpath != "" || len(strings.TrimSpace(oc.Curlpath)) > 0 {
		_, e := os.Stat(oc.Curlpath)
		if e != nil {
			return e
		}
	} else {
		//如果没配置，则直接指定。
		oc.Curlpath = "/usr/bin/curl"
	}

	if oc.Ifname == "" || len(strings.TrimSpace(oc.Ifname)) == 0 {
		oc.Ifname = DefaultIfname
	}

	if checkedOpenssl {
		return nil
	}

	if oc.NoSearch {
		return errors.New("NoSearch requires specifying lib path")
	}

	if !checkedOpenssl {
		e := oc.checkOpenssl()
		if e != nil {
			return e
		}
	}

	s, e := checkCgroupPath(oc.CGroupPath)
	if e != nil {
		return e
	}
	oc.CGroupPath = s
	return nil
}
