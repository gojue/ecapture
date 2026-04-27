// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package domain

// MonoNsEvent is implemented by events that carry a bpf monotonic timestamp (e.g. bpf_ktime_get_ns)
// used to reorder merged per-CPU perf buffer samples in userland.
type MonoNsEvent interface {
	Event
	PerfMonoNs() uint64
}

// AsMonoNsEvent returns e if it supports perf reorder ordering.
func AsMonoNsEvent(e Event) (MonoNsEvent, bool) {
	m, ok := e.(MonoNsEvent)
	return m, ok
}
