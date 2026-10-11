// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"testing"

	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
)

func TestApplyCommonConfig(t *testing.T) {
	runtimeOutput := &outputpipeline.RuntimeDependencies{}
	target := NewBaseConfig()
	target.RuntimeOutput = runtimeOutput
	common := CommonConfig{
		Pid:                101,
		Uid:                202,
		Debug:              true,
		Hex:                true,
		BTFMode:            BTFModeNonCore,
		ByteCodeFileMode:   ByteCodeFileNonCore,
		PerCpuMapSize:      303 * 4096,
		TruncateSize:       404,
		EventCollectorAddr: "/tmp/common-events.log",
		EventRotateSizeMB:  5,
		EventRotateSeconds: 6,
		CGroupPath:         "/sys/fs/cgroup/example",
		PerfReorder:        true,
		PerfReorderLagMs:   7,
	}

	for i := 0; i < 2; i++ {
		if err := ApplyCommonConfig(target, common); err != nil {
			t.Fatal(err)
		}
	}
	got, err := CommonConfigFrom(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != common {
		t.Fatalf("common config = %#v, want %#v", got, common)
	}
	if target.RuntimeOutput != runtimeOutput {
		t.Fatal("applying serializable common config replaced runtime dependencies")
	}
}

func TestCommonConfigPatchPresenceAndApply(t *testing.T) {
	patch, err := DecodeCommonConfigPatch([]byte(`{
		"pid": 0,
		"uid": 22,
		"debug": false,
		"is_hex": true,
		"btf_mode": 2,
		"byte_code_file_mode": 1,
		"per_cpu_map_size": 65536,
		"truncate_size": 99,
		"event_collector_addr": "",
		"event_rotate_size_mb": 0,
		"event_rotate_seconds": 17,
		"cgroup_path": "",
		"perf_reorder": false,
		"perf_reorder_lag_ms": 0
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if patch.EventCollectorAddr == nil || patch.EventRotateSizeMB == nil || patch.Pid == nil {
		t.Fatal("explicit zero values were treated as missing")
	}
	if *patch.EventCollectorAddr != "" || *patch.EventRotateSizeMB != 0 || *patch.Pid != 0 {
		t.Fatal("explicit zero values were not preserved")
	}

	target := NewBaseConfig()
	target.Pid = 999
	target.EventCollectorAddr = "/tmp/old.log"
	target.EventRotateSizeMB = 8
	if err = patch.Apply(target); err != nil {
		t.Fatal(err)
	}
	if target.Pid != 0 || target.Uid != 22 || target.EventCollectorAddr != "" || target.EventRotateSizeMB != 0 {
		t.Fatalf("patched base config = %#v", target)
	}
	if target.EventRotateSeconds != 17 || !target.IsHex || target.BtfMode != 2 {
		t.Fatalf("patched common fields missing: %#v", target)
	}
}

func TestMergeReloadOutput(t *testing.T) {
	current := NewBaseConfig()
	current.EventCollectorAddr = "/tmp/original.log"
	current.EventRotateSizeMB = 11
	current.EventRotateSeconds = 12

	tests := []struct {
		name        string
		jsonBody    string
		wantAddr    string
		wantSize    uint16
		wantSeconds uint16
	}{
		{
			name:        "missing inherits",
			jsonBody:    `{}`,
			wantAddr:    current.EventCollectorAddr,
			wantSize:    current.EventRotateSizeMB,
			wantSeconds: current.EventRotateSeconds,
		},
		{
			name:        "explicit values replace",
			jsonBody:    `{"event_collector_addr":"/tmp/new.log","event_rotate_size_mb":21,"event_rotate_seconds":22}`,
			wantAddr:    "/tmp/new.log",
			wantSize:    21,
			wantSeconds: 22,
		},
		{
			name:        "explicit clear remains clear",
			jsonBody:    `{"event_collector_addr":"","event_rotate_size_mb":0,"event_rotate_seconds":0}`,
			wantAddr:    "",
			wantSize:    0,
			wantSeconds: 0,
		},
		{
			name:        "partial rotation inherits by field",
			jsonBody:    `{"event_rotate_size_mb":0}`,
			wantAddr:    current.EventCollectorAddr,
			wantSize:    0,
			wantSeconds: current.EventRotateSeconds,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := NewBaseConfig()
			patch, err := DecodeCommonConfigPatch([]byte(test.jsonBody))
			if err != nil {
				t.Fatal(err)
			}
			if err = patch.Apply(candidate); err != nil {
				t.Fatal(err)
			}
			if err = MergeReloadOutput(current, candidate, patch); err != nil {
				t.Fatal(err)
			}
			if candidate.EventCollectorAddr != test.wantAddr ||
				candidate.EventRotateSizeMB != test.wantSize ||
				candidate.EventRotateSeconds != test.wantSeconds {
				t.Fatalf("merged output = (%q, %d, %d), want (%q, %d, %d)",
					candidate.EventCollectorAddr,
					candidate.EventRotateSizeMB,
					candidate.EventRotateSeconds,
					test.wantAddr,
					test.wantSize,
					test.wantSeconds,
				)
			}
		})
	}
}
