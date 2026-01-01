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

package factory

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gojue/ecapture/internal/domain"
)

// mockProbe implements domain.Probe for testing
type mockProbe struct {
	name string
}

func (m *mockProbe) Initialize(ctx context.Context, config domain.Configuration, dispatcher domain.EventDispatcher) error {
	return nil
}
func (m *mockProbe) Start(ctx context.Context) error { return nil }
func (m *mockProbe) Stop(ctx context.Context) error  { return nil }
func (m *mockProbe) Close() error                    { return nil }
func (m *mockProbe) Name() string                    { return m.name }
func (m *mockProbe) IsRunning() bool                 { return false }
func (m *mockProbe) Events() []*ebpf.Map             { return nil }

func TestNewProbeFactory(t *testing.T) {
	factory := NewProbeFactory()
	if factory == nil {
		t.Fatal("NewProbeFactory returned nil")
	}

	probes := factory.GetSupportedProbes()
	if len(probes) != 0 {
		t.Errorf("expected 0 probes, got %d", len(probes))
	}
}

func TestRegisterProbeConstructor(t *testing.T) {
	factory := NewProbeFactory()

	constructor := func() (domain.Probe, error) {
		return &mockProbe{name: "test"}, nil
	}

	err := factory.RegisterProbeConstructor(ProbeTypeBash, constructor)
	if err != nil {
		t.Fatalf("RegisterProbeConstructor() error = %v", err)
	}

	probes := factory.GetSupportedProbes()
	if len(probes) != 1 {
		t.Errorf("expected 1 probe, got %d", len(probes))
	}
}

func TestRegisterProbeConstructorDuplicate(t *testing.T) {
	factory := NewProbeFactory()

	constructor := func() (domain.Probe, error) {
		return &mockProbe{name: "test"}, nil
	}

	_ = factory.RegisterProbeConstructor(ProbeTypeBash, constructor)
	err := factory.RegisterProbeConstructor(ProbeTypeBash, constructor)

	if err == nil {
		t.Error("RegisterProbeConstructor() should return error for duplicate type")
	}
}

func TestCreateProbe(t *testing.T) {
	factory := NewProbeFactory()

	constructor := func() (domain.Probe, error) {
		return &mockProbe{name: "test-probe"}, nil
	}

	_ = factory.RegisterProbeConstructor(ProbeTypeBash, constructor)

	probe, err := factory.CreateProbe(ProbeTypeBash)
	if err != nil {
		t.Fatalf("CreateProbe() error = %v", err)
	}

	if probe.Name() != "test-probe" {
		t.Errorf("expected name 'test-probe', got '%s'", probe.Name())
	}
}

func TestCreateProbeNotFound(t *testing.T) {
	factory := NewProbeFactory()

	_, err := factory.CreateProbe(ProbeTypeBash)
	if err == nil {
		t.Error("CreateProbe() should return error for unregistered type")
	}
}

func TestCreateProbeConstructorError(t *testing.T) {
	factory := NewProbeFactory()

	constructor := func() (domain.Probe, error) {
		return nil, errors.New("construction failed")
	}

	_ = factory.RegisterProbeConstructor(ProbeTypeBash, constructor)

	_, err := factory.CreateProbe(ProbeTypeBash)
	if err == nil {
		t.Error("CreateProbe() should return error when constructor fails")
	}
}

func TestGlobalFactory(t *testing.T) {
	// Note: This test uses the global factory, which may have side effects
	// In production code, consider using a fresh factory for each test

	constructor := func() (domain.Probe, error) {
		return &mockProbe{name: "global-test"}, nil
	}

	// Use a unique probe type to avoid conflicts
	testType := ProbeType("test-global-probe")

	err := RegisterProbe(testType, constructor)
	if err != nil {
		t.Fatalf("RegisterProbe() error = %v", err)
	}

	probe, err := CreateProbe(testType)
	if err != nil {
		t.Fatalf("CreateProbe() error = %v", err)
	}

	if probe.Name() != "global-test" {
		t.Errorf("expected name 'global-test', got '%s'", probe.Name())
	}
}
