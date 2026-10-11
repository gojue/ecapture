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

package bytecode

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"

	"github.com/gojue/ecapture/v2/assets"
	"github.com/gojue/ecapture/v2/internal/config"
)

// Mode is the resolved bytecode variant used by a probe generation.
type Mode uint8

const (
	ModeCore    Mode = Mode(config.BTFModeCore)
	ModeNonCore Mode = Mode(config.BTFModeNonCore)
)

func (m Mode) String() string {
	switch m {
	case ModeCore:
		return "core"
	case ModeNonCore:
		return "noncore"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// Detector reports whether usable kernel BTF is available.
type Detector func() (bool, error)

// AssetExists reports whether a concrete go-bindata key is embedded.
type AssetExists func(name string) bool

type cachedDetector struct {
	detect    Detector
	once      sync.Once
	available bool
	err       error
}

func newCachedDetector(detect Detector) *cachedDetector {
	return &cachedDetector{detect: detect}
}

func (d *cachedDetector) Detect() (bool, error) {
	d.once.Do(func() {
		if d.detect == nil {
			d.err = errors.New("BTF detector is nil")
			return
		}
		d.available, d.err = d.detect()
	})
	return d.available, d.err
}

var processBTFDetector = newCachedDetector(detectKernelBTF)

// Selector resolves a probe generation's bytecode mode exactly once and then
// maps every probe-specific base name to an embedded asset of that mode.
type Selector struct {
	requestedMode uint8
	assetMode     uint8
	detector      Detector
	assetExists   AssetExists

	once     sync.Once
	resolved Mode
	err      error
}

// NewSelector creates the production selector backed by the process-wide BTF
// detector cache and the current go-bindata catalog.
func NewSelector(requestedMode, assetMode uint8) *Selector {
	return NewSelectorWithDependencies(
		requestedMode,
		assetMode,
		processBTFDetector.Detect,
		embeddedAssetExists,
	)
}

// NewSelectorWithDependencies creates a selector with injectable kernel and
// asset probes for deterministic unit tests.
func NewSelectorWithDependencies(
	requestedMode, assetMode uint8,
	detector Detector,
	assetExists AssetExists,
) *Selector {
	return &Selector{
		requestedMode: requestedMode,
		assetMode:     assetMode,
		detector:      detector,
		assetExists:   assetExists,
	}
}

// RequestedMode returns the user-facing BTF mode supplied to the selector.
func (s *Selector) RequestedMode() uint8 {
	return s.requestedMode
}

// AssetMode returns the build-time embedded asset set.
func (s *Selector) AssetMode() uint8 {
	return s.assetMode
}

// Resolve determines and memoizes the bytecode mode for this probe generation.
func (s *Selector) Resolve() (Mode, error) {
	s.once.Do(s.resolve)
	return s.resolved, s.err
}

func (s *Selector) resolve() {
	if s.requestedMode > config.BTFModeNonCore {
		s.err = fmt.Errorf("invalid BTF mode %d", s.requestedMode)
		return
	}
	if s.assetMode > config.ByteCodeFileNonCore {
		s.err = fmt.Errorf("invalid embedded asset mode %d", s.assetMode)
		return
	}

	switch s.requestedMode {
	case config.BTFModeCore:
		if !assetModeContains(s.assetMode, ModeCore) {
			s.err = unavailableModeError(ModeCore, s.assetMode)
			return
		}
		available, err := s.detectBTF()
		if err != nil {
			s.err = fmt.Errorf("explicit CO-RE mode cannot verify kernel BTF availability: %w", err)
			return
		}
		if !available {
			s.err = errors.New("explicit CO-RE mode requires usable kernel BTF, but none was found")
			return
		}
		s.resolved = ModeCore

	case config.BTFModeNonCore:
		if !assetModeContains(s.assetMode, ModeNonCore) {
			s.err = unavailableModeError(ModeNonCore, s.assetMode)
			return
		}
		s.resolved = ModeNonCore

	case config.BTFModeAutoDetect:
		// A noncore-only binary is always safe to run without probing BTF. This
		// is also what lets the default --btf=0 work in minimal containers.
		if s.assetMode == config.ByteCodeFileNonCore {
			s.resolved = ModeNonCore
			return
		}

		available, err := s.detectBTF()
		if err != nil {
			s.err = fmt.Errorf("auto BTF detection failed: %w", err)
			return
		}
		if available {
			s.resolved = ModeCore
			return
		}
		if !assetModeContains(s.assetMode, ModeNonCore) {
			s.err = fmt.Errorf(
				"auto BTF detection found no usable kernel BTF, but binary asset mode %q has no non-CO-RE bytecode",
				config.ByteCodeFileModeName(s.assetMode),
			)
			return
		}
		s.resolved = ModeNonCore
	}
}

func (s *Selector) detectBTF() (bool, error) {
	if s.detector == nil {
		return false, errors.New("BTF detector is nil")
	}
	return s.detector()
}

// Select returns the concrete embedded key for baseName. It never falls back
// after Resolve: a missing selected asset is an explicit build/runtime contract
// error instead of a silent mode switch.
func (s *Selector) Select(baseName string) (string, error) {
	mode, err := s.Resolve()
	if err != nil {
		return "", err
	}
	name, err := AssetName(baseName, mode)
	if err != nil {
		return "", err
	}
	if s.assetExists == nil {
		return "", errors.New("embedded asset catalog is nil")
	}
	if !s.assetExists(name) {
		return "", fmt.Errorf(
			"selected %s asset %q is not embedded in binary asset mode %q",
			mode,
			name,
			config.ByteCodeFileModeName(s.assetMode),
		)
	}
	return name, nil
}

// AssetName applies the repository's canonical core/noncore suffix contract.
func AssetName(baseName string, mode Mode) (string, error) {
	if !strings.HasSuffix(baseName, ".o") || len(baseName) <= len(".o") {
		return "", fmt.Errorf("invalid bytecode base name %q: want an .o suffix", baseName)
	}
	prefix := strings.TrimSuffix(baseName, ".o")
	switch mode {
	case ModeCore:
		return prefix + "_core.o", nil
	case ModeNonCore:
		return prefix + "_noncore.o", nil
	default:
		return "", fmt.Errorf("invalid resolved bytecode mode %d", mode)
	}
}

func unavailableModeError(mode Mode, assetMode uint8) error {
	return fmt.Errorf(
		"explicit %s mode is unavailable: binary asset mode %q does not embed %s bytecode",
		mode,
		config.ByteCodeFileModeName(assetMode),
		mode,
	)
}

func assetModeContains(assetMode uint8, mode Mode) bool {
	return assetMode == config.ByteCodeFileAll ||
		(assetMode == config.ByteCodeFileCore && mode == ModeCore) ||
		(assetMode == config.ByteCodeFileNonCore && mode == ModeNonCore)
}

func embeddedAssetExists(name string) bool {
	for _, embeddedName := range assets.AssetNames() {
		if embeddedName == name {
			return true
		}
	}
	return false
}

func detectKernelBTF() (bool, error) {
	_, err := btf.LoadKernelSpec()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, btf.ErrNotSupported) {
		return false, nil
	}
	return false, err
}
