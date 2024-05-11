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
)

const (
	LdLoadPath       = "/etc/ld.so.conf"
	ElfArchIsandroid = false
)

/*
1, the RPATH binary header (set at build-time) of the library causing the lookup (if any)
2, the RPATH binary header (set at build-time) of the executable
3, the LD_LIBRARY_PATH environment variable (set at run-time)
4, the RUNPATH binary header (set at build-time) of the executable
5, /etc/ld.so.cache
6, base library directories (/lib and /usr/lib)
ref: http://blog.tremily.us/posts/rpath/
*/
var (
	default_so_paths = []string{
		"/lib",
		"/usr/lib",
		"/usr/lib64",
		"/lib64",
	}

	// DefaultMapSizePerCpu default: 4MB
	DefaultMapSizePerCpu = os.Getpagesize() * 1024
)

func GetDynLibDirs() []string {
	dirs, err := ParseDynLibConf(LdLoadPath)
	if err != nil {
		return default_so_paths
	}
	return append(dirs, "/lib64", "/usr/lib64")
}
