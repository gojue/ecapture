// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"testing"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/probe/bytecode"
)

func TestBytecodeModeStableAcrossValidateInitializeAndStart(t *testing.T) {
	detectorCalls := 0
	probe := NewBaseProbe("selector-stability")
	probe.newSelector = func(requestedMode, assetMode uint8) *bytecode.Selector {
		return bytecode.NewSelectorWithDependencies(
			requestedMode,
			assetMode,
			func() (bool, error) {
				detectorCalls++
				return detectorCalls == 1, nil
			},
			func(string) bool { return true },
		)
	}
	cfg := config.NewBaseConfig()
	ctx := context.Background()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("first Validate() error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("second Validate() error = %v", err)
	}
	if err := probe.Initialize(ctx, cfg); err != nil {
		t.Fatalf("first Initialize() error = %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := probe.Start(ctx); err != nil {
			t.Fatalf("Start(%d) error = %v", i, err)
		}
		name, err := probe.SelectBytecode("bytecode/bash_kern.o")
		if err != nil {
			t.Fatalf("SelectBytecode(%d) error = %v", i, err)
		}
		if name != "bytecode/bash_kern_core.o" {
			t.Fatalf("SelectBytecode(%d) = %q, want core asset", i, name)
		}
		if err = probe.Stop(ctx); err != nil {
			t.Fatalf("Stop(%d) error = %v", i, err)
		}
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := probe.Initialize(ctx, cfg); err != nil {
		t.Fatalf("second Initialize() error = %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if detectorCalls != 1 {
		t.Fatalf("detector calls = %d, want 1", detectorCalls)
	}
}
