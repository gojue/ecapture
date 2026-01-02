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

// Factory registration deferred - NSPR probe uses simplified stub implementation
// in Phase 4 Plan B that doesn't require full domain.Configuration interface.
// Use nspr.NewProbe() directly to create instances.
//
// Full factory integration will be added in future PRs when:
// - Config implements domain.Configuration interface
// - eBPF implementation is complete
// - Factory system supports simplified probe patterns
