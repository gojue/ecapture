//go:build !dynamic

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

package ebpf

import (
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
)

func injectPcapFilter(progSpec *ebpf.ProgramSpec, pcapFilter string) (*ebpf.ProgramSpec, error) {
	// Stub: pcap filter injection not available without the dynamic build tag.
	return progSpec, nil
}

// PrepareInsnPatchers prepares instruction patcher functions for the given eBPF functions and pcap filter.
// This stub returns an empty list; pcap filtering is only available when built with -tags dynamic.
func PrepareInsnPatchers(m *manager.Manager, ebpfFuncs []string, pcapFilter string) []manager.InstructionPatcherFunc {
	return nil
}
