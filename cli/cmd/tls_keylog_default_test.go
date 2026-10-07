//go:build !ecap_android

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

package cmd

import "testing"

func TestTLSKeylogFileDefaultsToExplicitOptIn(t *testing.T) {
	for _, test := range []struct {
		name       string
		defaultVal string
	}{
		{name: "openssl", defaultVal: opensslCmd.Flag("keylogfile").DefValue},
		{name: "gotls", defaultVal: gotlsCmd.Flag("keylogfile").DefValue},
		{name: "gnutls", defaultVal: gnutlsCmd.Flag("keylogfile").DefValue},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.defaultVal != "" {
				t.Fatalf("keylogfile default = %q, want empty explicit opt-in", test.defaultVal)
			}
		})
	}
}
