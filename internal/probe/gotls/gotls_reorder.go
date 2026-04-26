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
	"sort"
)

type goTLSPerfReorder struct {
	lagNs      uint64
	maxPending int
	buf        []*GoTLSDataEvent
}

func newGoTLSPerfReorder(lagNs uint64) *goTLSPerfReorder {
	return &goTLSPerfReorder{
		lagNs:      lagNs,
		maxPending: 1024,
	}
}

func (r *goTLSPerfReorder) less(i, j int) bool {
	return LessGoTLSDataEventByPerfOrder(r.buf[i], r.buf[j])
}

// flushAll emits the entire buffer in stable probe order (e.g. on reader shutdown).
func (r *goTLSPerfReorder) flushAll() []*GoTLSDataEvent {
	if len(r.buf) == 0 {
		return nil
	}
	sort.SliceStable(r.buf, r.less)
	out := r.buf
	r.buf = nil
	return out
}

func (r *goTLSPerfReorder) push(ev *GoTLSDataEvent) []*GoTLSDataEvent {
	r.buf = append(r.buf, ev)
	if len(r.buf) >= r.maxPending {
		return r.flushPressure()
	}
	return r.flushByLag()
}

func (r *goTLSPerfReorder) flushPressure() []*GoTLSDataEvent {
	sort.SliceStable(r.buf, r.less)
	n := len(r.buf) / 2
	if n == 0 {
		n = 1
	}
	out := make([]*GoTLSDataEvent, n)
	copy(out, r.buf[:n])
	r.buf = append([]*GoTLSDataEvent(nil), r.buf[n:]...)
	return out
}

func (r *goTLSPerfReorder) flushByLag() []*GoTLSDataEvent {
	if len(r.buf) <= 1 {
		return nil
	}
	var maxNs, minNs int64 = -1, -1
	for _, x := range r.buf {
		v := int64(x.BpfMonoNs)
		if maxNs < v {
			maxNs = v
		}
		if minNs < 0 || v < minNs {
			minNs = v
		}
	}
	if maxNs-minNs < int64(r.lagNs) {
		return nil
	}
	cutoff := maxNs - int64(r.lagNs)
	var flush []*GoTLSDataEvent
	var keep []*GoTLSDataEvent
	for _, x := range r.buf {
		if int64(x.BpfMonoNs) <= cutoff {
			flush = append(flush, x)
		} else {
			keep = append(keep, x)
		}
	}
	r.buf = keep
	sort.SliceStable(flush, func(i, j int) bool {
		return LessGoTLSDataEventByPerfOrder(flush[i], flush[j])
	})
	return flush
}
