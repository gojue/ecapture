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

package nspr

// NOTE: Factory registration is not implemented for NSPR probe in Phase 4.
//
// The NSPR probe currently uses a simplified interface signature:
//   Initialize(ctx context.Context, config interface{}, dispatcher interface{}) error
//
// The domain.Probe interface requires:
//   Initialize(ctx context.Context, config domain.Configuration, dispatcher domain.EventDispatcher) error
//
// To enable factory registration, the following changes are needed:
// 1. Update Config to implement domain.Configuration interface
// 2. Update probe Initialize signature to use typed interfaces
// 3. Implement full domain.Probe interface (Events(), IsRunning(), etc.)
// 4. Complete eBPF implementation
//
// For now, create NSPR probes directly using:
//   probe, err := nspr.NewProbe()
//   probe.Initialize(ctx, config, dispatcher)
//
// Factory registration will be added in a future PR.
