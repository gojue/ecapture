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
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultIfname = "eth0"
)

func (oc *OpensslConfig) checkOpenssl() error {
	var e error
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
	return nil
}

func (oc *OpensslConfig) checkConnect() error {
	var sharedObjects = []string{
		"libpthread.so.0", // ubuntu 21.04 server
		"libc.so.6",       // ubuntu 21.10 server
		"libc.so",         // Android
	}

	var funcName = ""
	var found bool
	var e error
	for _, so := range sharedObjects {
		_, e = os.Stat(X86BinaryPrefix)
		prefix := X86BinaryPrefix
		if e != nil {
			prefix = OthersBinaryPrefix
		}
		oc.Pthread = filepath.Join(prefix, so)
		_, e = os.Stat(oc.Pthread)
		if e != nil {
			// search all of sharedObjects
			//return e
			continue
		}

		_elf, e := elf.Open(oc.Pthread)
		if e != nil {
			//return e
			continue
		}

		dynamicSymbols, err := _elf.DynamicSymbols()
		if err != nil {
			//return err
			continue
		}

		//
		for _, sym := range dynamicSymbols {
			if sym.Name != "connect" {
				continue
			}
			//fmt.Printf("\tsize:%d,  name:%s,  offset:%d\n", sym.Size, sym.Name, 0)
			funcName = sym.Name
			found = true
			break
		}

		// if found
		if found && funcName != "" {
			break
		}
	}

	//如果没找到，则报错。
	if !found || funcName == "" {
		return errors.New(fmt.Sprintf("cant found 'connect' function to hook in files::%v", sharedObjects))
	}
	return nil
}

func (oc *OpensslConfig) Check() error {
	oc.IsAndroid = false
	var checkedOpenssl, checkedConnect bool
	// 如果readline 配置，且存在，则直接返回。
	if oc.Openssl != "" || len(strings.TrimSpace(oc.Openssl)) > 0 {
		_, e := os.Stat(oc.Openssl)
		if e != nil {
			return e
		}
		oc.ElfType = ElfTypeSo
		checkedOpenssl = true
	}
	/*
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

			if oc.Pthread != "" || len(strings.TrimSpace(oc.Pthread)) > 0 {
			_, e := os.Stat(oc.Pthread)
			if e != nil {
				return e
			}
			checkedConnect = true
		}
	*/
	if oc.Ifname == "" || len(strings.TrimSpace(oc.Ifname)) == 0 {
		oc.Ifname = DefaultIfname
	}

	if checkedConnect && checkedOpenssl {
		return nil
	}

	if !checkedOpenssl {
		e := oc.checkOpenssl()
		if e != nil {
			return e
		}
	}

	if !checkedConnect {
		return oc.checkConnect()
	}
	s, e := checkCgroupPath(oc.CGroupPath)
	if e != nil {
		return e
	}
	oc.CGroupPath = s
	return nil
}
