//go:build !ebpfassets

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

// Package assets provides embedded eBPF bytecode assets.
// This stub is used when the real assets have not been generated yet
// (i.e. when building without the 'ebpfassets' build tag).
// Run `make assets` to generate the real assets/ebpf_probe.go file,
// which must be built with -tags ebpfassets.
package assets

import "fmt"

// Asset returns the contents of the named embedded asset.
// This stub always returns an error; the real implementation is generated
// by `make assets` and requires the 'ebpfassets' build tag.
func Asset(name string) ([]byte, error) {
	return nil, fmt.Errorf("eBPF asset %q not available: run `make assets` to generate embedded bytecode", name)
}

// AssetNames returns the names of all embedded assets.
func AssetNames() []string {
	return nil
}
