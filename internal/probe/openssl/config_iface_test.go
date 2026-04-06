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

import (
	"net"
	"testing"
)

func TestIfaceHasAddr_Loopback(t *testing.T) {
	// The loopback interface (lo) should always be present and have an address
	// on Linux. On non-Linux or unusual environments, skip.
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("loopback interface 'lo' not available on this host")
	}
	if iface.Flags&net.FlagUp == 0 {
		t.Skip("loopback interface 'lo' is not UP")
	}
	if !ifaceHasAddr("lo") {
		t.Error("ifaceHasAddr returned false for loopback interface 'lo' which is UP")
	}
}

func TestIfaceHasAddr_NonExistent(t *testing.T) {
	// A completely made-up interface name should return false.
	if ifaceHasAddr("nonexistent_iface_xyz") {
		t.Error("ifaceHasAddr returned true for a non-existent interface")
	}
}

func TestFirstUpNonLoopbackInterface(t *testing.T) {
	name := firstUpNonLoopbackInterface()
	if name == "" {
		t.Skip("no active non-loopback interface found on this host")
	}

	// The returned interface must actually be up and have addresses.
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("firstUpNonLoopbackInterface returned %q but InterfaceByName failed: %v", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		t.Errorf("firstUpNonLoopbackInterface returned %q which is not UP", name)
	}
	if iface.Flags&net.FlagLoopback != 0 {
		t.Errorf("firstUpNonLoopbackInterface returned loopback interface %q", name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatalf("cannot get addresses for %q: %v", name, err)
	}
	if len(addrs) == 0 {
		t.Errorf("firstUpNonLoopbackInterface returned %q which has no addresses", name)
	}
}
