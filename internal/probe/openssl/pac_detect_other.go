//go:build !ecap_android
// +build !ecap_android

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

package openssl

// PACInfo holds the results of ARM64 Pointer Authentication Code detection.
type PACInfo struct {
	// CPUSupport indicates whether the CPU supports PAC (paca or pacg feature flags).
	CPUSupport bool
	// LibraryPAC indicates whether the target SSL library was compiled with PAC support.
	LibraryPAC bool
	// Detected is true when PAC is likely active (CPU supports it on ARM64).
	Detected bool
}

// DetectPACInfo is a stub for non-Linux platforms. PAC detection is only
// supported on Linux/ARM64 systems.
func DetectPACInfo(libsslPath string) PACInfo {
	return PACInfo{}
}
