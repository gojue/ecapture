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

package gotls

import "net"

// ifaceHasAddr returns true when the named interface exists, is up, and has at
// least one address.
func ifaceHasAddr(name string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	return len(addrs) > 0
}

// firstUpNonLoopbackInterface walks all network interfaces and returns the
// name of the first non-loopback interface that is up and has an address.
// Note: this is not necessarily the default-route interface; it may return
// virtual bridges (e.g. docker0) before the real egress interface.
func firstUpNonLoopbackInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return iface.Name
	}
	return ""
}

// setDefaultIfname detects an active network interface when Ifname is empty.
// On real devices wlan0 is common, but in emulators networking may use eth0
// or another interface. This function tries to find an interface that is up
// and has at least one IP address.
func (c *Config) setDefaultIfname() {
	if c.Ifname != "" {
		return
	}

	// Try the common default first.
	if ifaceHasAddr("wlan0") {
		c.Ifname = "wlan0"
		return
	}

	// Fallback: iterate all interfaces looking for one that is up and has an
	// address, skipping loopback.
	if name := firstUpNonLoopbackInterface(); name != "" {
		c.Ifname = name
		return
	}

	// Last resort: keep the historical default so the error message is clear.
	c.Ifname = "wlan0"
}
