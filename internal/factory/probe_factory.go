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
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// ProbeType defines the types of probes available.
type ProbeType string

const (
	ProbeTypeBash     ProbeType = "bash"
	ProbeTypeZsh      ProbeType = "zsh"
	ProbeTypeMySQL    ProbeType = "mysql"
	ProbeTypePostgres ProbeType = "postgres"
	ProbeTypeOpenSSL  ProbeType = "openssl"
	ProbeTypeGnuTLS   ProbeType = "gnutls"
	ProbeTypeNSPR     ProbeType = "nspr"
	ProbeTypeGoTLS    ProbeType = "gotls"
)

// ProbeFactory defines the interface for creating probes.
type ProbeFactory interface {
	// CreateProbe creates a new probe instance of the specified type.
	CreateProbe(probeType ProbeType) (domain.Probe, error)

	// RegisterProbeConstructor registers a constructor for a probe type.
	RegisterProbeConstructor(probeType ProbeType, constructor ProbeConstructor) error

	// GetSupportedProbes returns a list of all supported probe types.
	GetSupportedProbes() []ProbeType
}

// ProbeConstructor is a function that creates a new probe instance.
type ProbeConstructor func() (domain.Probe, error)

// defaultFactory implements ProbeFactory.
type defaultFactory struct {
	constructors map[ProbeType]ProbeConstructor
}

// NewProbeFactory creates a new probe factory.
func NewProbeFactory() ProbeFactory {
	return &defaultFactory{
		constructors: make(map[ProbeType]ProbeConstructor),
	}
}

// CreateProbe creates a new probe instance.
func (f *defaultFactory) CreateProbe(probeType ProbeType) (domain.Probe, error) {
	constructor, exists := f.constructors[probeType]
	if !exists {
		return nil, errors.NewResourceNotFoundError(fmt.Sprintf("probe type: %s", probeType))
	}

	probe, err := constructor()
	if err != nil {
		return nil, errors.Wrap(errors.ErrCodeProbeInit, fmt.Sprintf("failed to construct probe of type '%s'", probeType), err)
	}

	return probe, nil
}

// RegisterProbeConstructor registers a constructor for a probe type.
func (f *defaultFactory) RegisterProbeConstructor(probeType ProbeType, constructor ProbeConstructor) error {
	if constructor == nil {
		return errors.New(errors.ErrCodeConfiguration, "constructor cannot be nil")
	}

	if _, exists := f.constructors[probeType]; exists {
		return errors.New(errors.ErrCodeConfiguration, fmt.Sprintf("probe type '%s' already registered", probeType))
	}

	f.constructors[probeType] = constructor
	return nil
}

// GetSupportedProbes returns a list of all supported probe types.
func (f *defaultFactory) GetSupportedProbes() []ProbeType {
	probes := make([]ProbeType, 0, len(f.constructors))
	for probeType := range f.constructors {
		probes = append(probes, probeType)
	}
	return probes
}

// Global factory instance
var globalFactory = NewProbeFactory()

// RegisterProbe registers a probe constructor with the global factory.
func RegisterProbe(probeType ProbeType, constructor ProbeConstructor) error {
	return globalFactory.RegisterProbeConstructor(probeType, constructor)
}

// CreateProbe creates a probe using the global factory.
func CreateProbe(probeType ProbeType) (domain.Probe, error) {
	return globalFactory.CreateProbe(probeType)
}

// GetSupportedProbes returns supported probes from the global factory.
func GetSupportedProbes() []ProbeType {
	return globalFactory.GetSupportedProbes()
}
