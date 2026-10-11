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

package http

import (
	"sync"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
)

// ConfigUpdate carries a decoded candidate plus common-field presence and an
// acknowledgement delivered only after the runtime accepts or rejects the
// switch.
type ConfigUpdate struct {
	Config      domain.Configuration
	CommonPatch config.CommonConfigPatch

	result chan error
	once   sync.Once
}

func newConfigUpdate(candidate domain.Configuration, patch config.CommonConfigPatch) *ConfigUpdate {
	return &ConfigUpdate{
		Config:      candidate,
		CommonPatch: patch,
		result:      make(chan error, 1),
	}
}

// Result reports whether the runtime successfully activated the candidate.
func (u *ConfigUpdate) Result() <-chan error {
	return u.result
}

// Complete acknowledges the update exactly once.
func (u *ConfigUpdate) Complete(err error) {
	u.once.Do(func() {
		u.result <- err
		close(u.result)
	})
}
