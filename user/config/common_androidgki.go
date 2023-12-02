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
)

// https://source.android.com/devices/architecture/vndk/linker-namespace
var (
	default_so_paths = []string{
		"/data/asan/system/lib64",
		"/apex/com.android.conscrypt/lib64",
		"/apex/com.android.runtime/lib64/bionic",
	}
	DefaultMapSizePerCpu = os.Getpagesize() * 512
)

const ElfArchIsandroid = true

func GetDynLibDirs() []string {
	return default_so_paths
}
