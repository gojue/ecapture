//go:build ecap_android
// +build ecap_android

// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

import "testing"

func TestConfig_DetectOSDoesNotAssumeBoringSSL(t *testing.T) {
	cfg := NewConfig()
	cfg.OpensslPath = "/tmp/libssl.so"

	if err := cfg.detectOS(); err != nil {
		t.Fatalf("detectOS() error = %v", err)
	}
	if !cfg.IsAndroid {
		t.Error("detectOS() did not identify Android")
	}
	if cfg.IsBoringSSL {
		t.Error("detectOS() assumed the library was BoringSSL")
	}
	if cfg.SslVersion != "" {
		t.Errorf("detectOS() fabricated SSL version %q", cfg.SslVersion)
	}
}
