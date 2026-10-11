// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bytecode

import (
	"errors"
	"strings"
	"testing"

	"github.com/gojue/ecapture/v2/internal/config"
)

func TestSelectorModeMatrix(t *testing.T) {
	detectorError := errors.New("detector failed")
	detectors := []struct {
		name      string
		available bool
		err       error
	}{
		{name: "available", available: true},
		{name: "unavailable", available: false},
		{name: "error", err: detectorError},
	}
	assetModes := []uint8{
		config.ByteCodeFileAll,
		config.ByteCodeFileCore,
		config.ByteCodeFileNonCore,
	}
	requestedModes := []uint8{
		config.BTFModeAutoDetect,
		config.BTFModeCore,
		config.BTFModeNonCore,
	}
	assetStates := []struct {
		name    string
		present bool
	}{
		{name: "asset-present", present: true},
		{name: "asset-missing", present: false},
	}

	for _, requestedMode := range requestedModes {
		for _, assetMode := range assetModes {
			for _, detector := range detectors {
				for _, assetState := range assetStates {
					name := strings.Join([]string{
						btfModeName(requestedMode),
						config.ByteCodeFileModeName(assetMode),
						detector.name,
						assetState.name,
					}, "/")
					t.Run(name, func(t *testing.T) {
						calls := 0
						selector := NewSelectorWithDependencies(
							requestedMode,
							assetMode,
							func() (bool, error) {
								calls++
								return detector.available, detector.err
							},
							func(string) bool { return assetState.present },
						)

						wantMode, resolveErr, wantCalls := matrixExpectation(
							requestedMode,
							assetMode,
							detector.available,
							detector.err,
						)
						gotName, err := selector.Select("bytecode/bash_kern.o")
						wantErr := resolveErr || !assetState.present
						if (err != nil) != wantErr {
							t.Fatalf("Select() error = %v, wantErr %v", err, wantErr)
						}
						if !wantErr {
							wantName, nameErr := AssetName("bytecode/bash_kern.o", wantMode)
							if nameErr != nil {
								t.Fatalf("AssetName() error = %v", nameErr)
							}
							if gotName != wantName {
								t.Fatalf("Select() = %q, want %q", gotName, wantName)
							}
						}
						if calls != wantCalls {
							t.Fatalf("detector calls = %d, want %d", calls, wantCalls)
						}
					})
				}
			}
		}
	}
}

func TestSelectorAssetAvailability(t *testing.T) {
	tests := []struct {
		name      string
		requested uint8
		assets    uint8
		btf       bool
		embedded  map[string]bool
		want      string
		wantErr   string
	}{
		{
			name:      "core asset present",
			requested: config.BTFModeCore,
			assets:    config.ByteCodeFileAll,
			btf:       true,
			embedded:  map[string]bool{"bytecode/bash_kern_core.o": true},
			want:      "bytecode/bash_kern_core.o",
		},
		{
			name:      "noncore asset present",
			requested: config.BTFModeNonCore,
			assets:    config.ByteCodeFileNonCore,
			embedded:  map[string]bool{"bytecode/bash_kern_noncore.o": true},
			want:      "bytecode/bash_kern_noncore.o",
		},
		{
			name:      "selected asset missing",
			requested: config.BTFModeCore,
			assets:    config.ByteCodeFileAll,
			btf:       true,
			embedded:  map[string]bool{"bytecode/bash_kern_noncore.o": true},
			wantErr:   "is not embedded",
		},
		{
			name:      "auto never falls back after core resolution",
			requested: config.BTFModeAutoDetect,
			assets:    config.ByteCodeFileAll,
			btf:       true,
			embedded:  map[string]bool{"bytecode/bash_kern_noncore.o": true},
			wantErr:   "bash_kern_core.o",
		},
		{
			name:      "explicit mode unavailable",
			requested: config.BTFModeCore,
			assets:    config.ByteCodeFileNonCore,
			btf:       true,
			embedded:  map[string]bool{"bytecode/bash_kern_noncore.o": true},
			wantErr:   "does not embed core bytecode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := NewSelectorWithDependencies(
				tt.requested,
				tt.assets,
				func() (bool, error) { return tt.btf, nil },
				func(name string) bool { return tt.embedded[name] },
			)
			got, err := selector.Select("bytecode/bash_kern.o")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Select() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Select() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Select() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectorResolutionIsStable(t *testing.T) {
	detectorCalls := 0
	selector := NewSelectorWithDependencies(
		config.BTFModeAutoDetect,
		config.ByteCodeFileAll,
		func() (bool, error) {
			detectorCalls++
			return detectorCalls == 1, nil
		},
		func(string) bool { return true },
	)

	for i := 0; i < 3; i++ {
		mode, err := selector.Resolve()
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if mode != ModeCore {
			t.Fatalf("Resolve() = %s, want core", mode)
		}
		name, err := selector.Select("bytecode/bash_kern.o")
		if err != nil {
			t.Fatalf("Select() error = %v", err)
		}
		if name != "bytecode/bash_kern_core.o" {
			t.Fatalf("Select() = %q", name)
		}
	}
	if detectorCalls != 1 {
		t.Fatalf("detector calls = %d, want 1", detectorCalls)
	}
}

func TestCachedDetectorIsStableAcrossSelectors(t *testing.T) {
	calls := 0
	cached := newCachedDetector(func() (bool, error) {
		calls++
		return calls == 1, nil
	})
	for i := 0; i < 2; i++ {
		selector := NewSelectorWithDependencies(
			config.BTFModeAutoDetect,
			config.ByteCodeFileAll,
			cached.Detect,
			func(string) bool { return true },
		)
		mode, err := selector.Resolve()
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if mode != ModeCore {
			t.Fatalf("Resolve() = %s, want core", mode)
		}
	}
	if calls != 1 {
		t.Fatalf("detector calls = %d, want 1", calls)
	}
}

func TestAssetNameRejectsInvalidInput(t *testing.T) {
	if _, err := AssetName("bytecode/bash_kern", ModeCore); err == nil {
		t.Fatal("AssetName() accepted a name without .o")
	}
	if _, err := AssetName("bytecode/bash_kern.o", Mode(99)); err == nil {
		t.Fatal("AssetName() accepted an invalid mode")
	}
}

func matrixExpectation(requestedMode, assetMode uint8, available bool, detectorErr error) (Mode, bool, int) {
	switch requestedMode {
	case config.BTFModeCore:
		if assetMode == config.ByteCodeFileNonCore {
			return 0, true, 0
		}
		if detectorErr != nil || !available {
			return 0, true, 1
		}
		return ModeCore, false, 1
	case config.BTFModeNonCore:
		if assetMode == config.ByteCodeFileCore {
			return 0, true, 0
		}
		return ModeNonCore, false, 0
	case config.BTFModeAutoDetect:
		if assetMode == config.ByteCodeFileNonCore {
			return ModeNonCore, false, 0
		}
		if detectorErr != nil {
			return 0, true, 1
		}
		if available {
			return ModeCore, false, 1
		}
		if assetMode == config.ByteCodeFileCore {
			return 0, true, 1
		}
		return ModeNonCore, false, 1
	default:
		return 0, true, 0
	}
}

func btfModeName(mode uint8) string {
	switch mode {
	case config.BTFModeAutoDetect:
		return "auto"
	case config.BTFModeCore:
		return "core"
	case config.BTFModeNonCore:
		return "noncore"
	default:
		return "invalid"
	}
}
