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
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestSelectCaptureInterface(t *testing.T) {
	link := func(index int, name string, traffic uint64) netlink.Link {
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Index: index, Name: name, Flags: net.FlagUp, EncapType: "ether",
			Statistics: &netlink.LinkStatistics{RxBytes: traffic},
		}}
	}
	route := func(index, family, metric int) netlink.Route {
		return netlink.Route{LinkIndex: index, Family: family, Priority: metric,
			Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST}
	}
	docker, eth, wifi := link(2, "docker0", 9000), link(3, "eth0", 500), link(4, "wlan0", 1000)
	down := link(5, "down0", 99999)
	down.Attrs().Flags = 0
	loopback := link(1, "lo", 99999)
	loopback.Attrs().Flags |= net.FlagLoopback
	tunnel := link(6, "tun0", 99999)
	tunnel.Attrs().EncapType = "none"
	noCarrier := link(7, "eth1", 99999)
	noCarrier.Attrs().OperState = netlink.OperLowerLayerDown
	defaults := []netlink.Link{docker, wifi, eth, down, loopback, tunnel, noCarrier}
	specific := route(4, netlink.FAMILY_V4, 0)
	_, specific.Dst, _ = net.ParseCIDR("192.0.2.0/24")
	explicitDefault := route(3, netlink.FAMILY_V6, 10)
	_, explicitDefault.Dst, _ = net.ParseCIDR("::/0")
	blackhole := route(4, netlink.FAMILY_V4, 0)
	blackhole.Type = unix.RTN_BLACKHOLE
	otherTable := route(4, netlink.FAMILY_V4, 0)
	otherTable.Table = 123
	dead := route(4, netlink.FAMILY_V4, 0)
	dead.Flags = unix.RTNH_F_LINKDOWN
	multipath := route(0, netlink.FAMILY_V4, 5)
	multipath.MultiPath = []*netlink.NexthopInfo{
		{LinkIndex: 2, Flags: unix.RTNH_F_DEAD}, {LinkIndex: 4}, {LinkIndex: 3},
	}
	for _, test := range []struct {
		name         string
		links        []netlink.Link
		routes       []netlink.Route
		want, reason string
	}{
		{"default route beats wlan and busy bridge", defaults, []netlink.Route{route(3, netlink.FAMILY_V4, 100)}, "eth0", "IPv4 default route"},
		{"lowest route metric", defaults, []netlink.Route{route(3, netlink.FAMILY_V4, 100), route(4, netlink.FAMILY_V4, 20)}, "wlan0", "metric 20"},
		{"route metric tie", defaults, []netlink.Route{route(4, netlink.FAMILY_V4, 20), route(3, netlink.FAMILY_V4, 20)}, "eth0", "default route"},
		{"IPv6 only default", defaults, []netlink.Route{explicitDefault}, "eth0", "IPv6 default route"},
		{"ignore unusable routes", defaults, []netlink.Route{specific, blackhole, otherTable, dead, route(5, netlink.FAMILY_V4, 0), route(6, netlink.FAMILY_V4, 0), route(7, netlink.FAMILY_V4, 0), route(1, netlink.FAMILY_V4, 0), route(3, netlink.FAMILY_V4, 100)}, "eth0", "default route"},
		{"multipath", defaults, []netlink.Route{multipath}, "eth0", "default route"},
		{"traffic fallback", []netlink.Link{eth, wifi}, nil, "wlan0", "traffic counters"},
		{"traffic tie", []netlink.Link{link(4, "wlan0", 50), link(3, "eth0", 50)}, nil, "eth0", "traffic counters"},
		{"no traffic fallback", []netlink.Link{link(4, "wlan0", 0), link(3, "eth0", 0)}, nil, "eth0", "up interface"},
		{"no usable links", []netlink.Link{down, loopback, tunnel, noCarrier}, nil, "", ""},
		{"empty inventory", nil, nil, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, reason := selectCaptureInterface(test.links, test.routes)
			if name != test.want || !strings.Contains(reason, test.reason) {
				t.Fatalf("selection = %q (%s), want %q (%s)", name, reason, test.want, test.reason)
			}
		})
	}
}

func TestDefaultInterfacePreservesExplicitChoice(t *testing.T) {
	for _, name := range []string{"lo", "eth-custom", "nonexistent-interface"} {
		cfg := NewConfig()
		cfg.Ifname = name
		for attempt := 0; attempt < 2; attempt++ {
			if err := cfg.setDefaultIfname(); err != nil {
				t.Fatal(err)
			}
			if cfg.Ifname != name || cfg.autoIfname != "" {
				t.Fatalf("explicit interface changed or marked automatic: %q / %q", cfg.Ifname, cfg.autoIfname)
			}
		}
	}
}

func TestDefaultInterfaceIsStable(t *testing.T) {
	cfg := NewConfig()
	if err := cfg.setDefaultIfname(); err != nil {
		t.Skipf("host has no usable capture interface: %v", err)
	}
	name, reason := cfg.Ifname, cfg.ifnameSelectionReason
	if name == "" || cfg.autoIfname != name || reason == "" {
		t.Fatalf("missing selection or provenance: %q / %q / %q", name, cfg.autoIfname, reason)
	}
	if err := cfg.setDefaultIfname(); err != nil {
		t.Fatal(err)
	}
	if cfg.Ifname != name || cfg.ifnameSelectionReason != reason {
		t.Fatal("repeated validation changed automatic interface selection")
	}
	encoded := string(cfg.Bytes())
	if strings.Contains(encoded, reason) || strings.Contains(encoded, "autoIfname") {
		t.Fatal("automatic selection provenance leaked into serialized config")
	}
}
