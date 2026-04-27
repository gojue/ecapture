// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package base

import (
	"sort"

	"github.com/gojue/ecapture/internal/domain"
)

type perfReorderItem struct {
	ev   domain.Event
	mono uint64
}

type perfLagReorder struct {
	lagNs      uint64
	maxPending int
	buf        []perfReorderItem
}

func newPerfLagReorder(lagNs uint64) *perfLagReorder {
	return &perfLagReorder{
		lagNs:      lagNs,
		maxPending: 1024,
	}
}

func (r *perfLagReorder) less(i, j int) bool {
	return r.buf[i].mono < r.buf[j].mono
}

// flushAll emits the entire buffer in stable time order (e.g. on reader shutdown).
func (r *perfLagReorder) flushAll() []domain.Event {
	if len(r.buf) == 0 {
		return nil
	}
	sort.SliceStable(r.buf, r.less)
	out := make([]domain.Event, len(r.buf))
	for i := range r.buf {
		out[i] = r.buf[i].ev
	}
	r.buf = nil
	return out
}

func (r *perfLagReorder) push(mn domain.MonoNsEvent) []domain.Event {
	r.buf = append(r.buf, perfReorderItem{ev: mn, mono: mn.PerfMonoNs()})
	if len(r.buf) >= r.maxPending {
		return r.flushPressure()
	}
	return r.flushByLag()
}

func (r *perfLagReorder) flushPressure() []domain.Event {
	sort.SliceStable(r.buf, r.less)
	n := len(r.buf) / 2
	if n == 0 {
		n = 1
	}
	out := make([]domain.Event, n)
	for i := 0; i < n; i++ {
		out[i] = r.buf[i].ev
	}
	r.buf = append([]perfReorderItem(nil), r.buf[n:]...)
	return out
}

func (r *perfLagReorder) flushByLag() []domain.Event {
	if len(r.buf) <= 1 {
		return nil
	}
	var maxNs, minNs int64 = -1, -1
	for _, x := range r.buf {
		v := int64(x.mono)
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
	var flush []perfReorderItem
	var keep []perfReorderItem
	for _, x := range r.buf {
		if int64(x.mono) <= cutoff {
			flush = append(flush, x)
		} else {
			keep = append(keep, x)
		}
	}
	r.buf = keep
	sort.SliceStable(flush, func(i, j int) bool {
		return flush[i].mono < flush[j].mono
	})
	out := make([]domain.Event, len(flush))
	for i := range flush {
		out[i] = flush[i].ev
	}
	return out
}
