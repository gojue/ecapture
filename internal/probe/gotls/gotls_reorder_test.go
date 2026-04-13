// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package gotls

import (
	"testing"
)

func TestGoTLSPerfReorder_flushByLag_ordersWithinCutoff(t *testing.T) {
	r := newGoTLSPerfReorder(10)
	_ = r.push(&GoTLSDataEvent{BpfMonoNs: 100, EmitCPU: 0, Seq: 2, DataLen: 1, Data: []byte{'b'}})
	out := r.push(&GoTLSDataEvent{BpfMonoNs: 50, EmitCPU: 0, Seq: 1, DataLen: 1, Data: []byte{'a'}})
	if len(out) != 1 {
		t.Fatalf("want 1 flushed (older mono), got %d", len(out))
	}
	if string(out[0].GetData()) != "a" {
		t.Fatalf("expected payload a, got %q", out[0].GetData())
	}
	out = r.push(&GoTLSDataEvent{BpfMonoNs: 120, EmitCPU: 0, Seq: 3, DataLen: 1, Data: []byte{'c'}})
	if len(out) != 1 || string(out[0].GetData()) != "b" {
		t.Fatalf("expected b flush, got %v", out)
	}
	rest := r.flushAll()
	if len(rest) != 1 || string(rest[0].GetData()) != "c" {
		t.Fatalf("remainder: %+v", rest)
	}
}
