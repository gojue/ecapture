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

package config

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/v2/internal/logger"
)

// CaptureInterfaceConfig is shared by TLS probes using packet capture.
// Selection provenance stays process-local and is excluded from JSON.
type CaptureInterfaceConfig struct {
	Ifname                string `json:"ifname"`
	autoIfname            string
	ifnameSelectionReason string
}

// SetDefaultIfname preserves explicit choices and resolves an interface only for
// packet capture. Validation can run repeatedly without changing the selection.
func (c *CaptureInterfaceConfig) SetDefaultIfname() error {
	if c.Ifname != "" {
		return nil
	}
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("cannot list capture interfaces; specify -i <interface>: %w", err)
	}
	routes, routeErr := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if routeErr != nil {
		// An interrupted dump must not be mistaken for a complete route table.
		routes = nil
	}
	name, reason := selectCaptureInterface(links, routes)
	if name == "" {
		return fmt.Errorf("no usable capture interface found; specify -i <interface> or use --text-source hook in text mode")
	}
	if routeErr != nil {
		reason += " (default-route lookup unavailable)"
	}
	c.Ifname, c.autoIfname, c.ifnameSelectionReason = name, name, reason
	return nil
}

// selectCaptureInterface prefers a main-table default route with the lowest
// metric, then historical traffic counters, then an up interface. Equal choices
// use the lowest interface index, independent of netlink dump order. Automatic
// selection is limited to Ethernet interfaces because the TC parser expects an
// Ethernet header; explicit choices are still validated by the existing path.
func selectCaptureInterface(links []netlink.Link, routes []netlink.Route) (string, string) {
	candidates := make(map[int]*netlink.LinkAttrs)
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Flags&net.FlagUp == 0 || attrs.Flags&net.FlagLoopback != 0 ||
			attrs.OperState == netlink.OperDown || attrs.OperState == netlink.OperLowerLayerDown ||
			attrs.EncapType != "ether" {
			continue
		}
		candidates[attrs.Index] = attrs
	}
	var best *netlink.LinkAttrs
	var bestMetric int
	var reason string
	for _, route := range routes {
		if route.Table != unix.RT_TABLE_MAIN || route.Type != unix.RTN_UNICAST ||
			(route.Family != netlink.FAMILY_V4 && route.Family != netlink.FAMILY_V6) ||
			route.Flags&(unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) != 0 {
			continue
		}
		if route.Dst != nil {
			ones, bits := route.Dst.Mask.Size()
			if bits == 0 || ones != 0 || !route.Dst.IP.IsUnspecified() {
				continue
			}
		}
		consider := func(index int) {
			attrs := candidates[index]
			if attrs == nil {
				return
			}
			if best == nil || route.Priority < bestMetric || (route.Priority == bestMetric && attrs.Index < best.Index) {
				best, bestMetric = attrs, route.Priority
				family := "IPv4"
				if route.Family == netlink.FAMILY_V6 {
					family = "IPv6"
				}
				reason = fmt.Sprintf("%s default route, metric %d", family, route.Priority)
			}
		}
		if len(route.MultiPath) == 0 {
			consider(route.LinkIndex)
		} else {
			for _, hop := range route.MultiPath {
				if hop != nil && hop.Flags&(unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) == 0 {
					consider(hop.LinkIndex)
				}
			}
		}
	}
	if best != nil {
		return best.Name, reason
	}
	var mostTraffic uint64
	for _, attrs := range candidates {
		var traffic uint64
		if attrs.Statistics != nil {
			traffic = attrs.Statistics.RxBytes + attrs.Statistics.TxBytes
		}
		if best == nil || traffic > mostTraffic || (traffic == mostTraffic && attrs.Index < best.Index) {
			best, mostTraffic = attrs, traffic
		}
	}
	if best == nil {
		return "", ""
	}
	if mostTraffic > 0 {
		return best.Name, "interface traffic counters (no usable default route)"
	}
	return best.Name, "up interface (no usable default route or recorded traffic)"
}

// LogCaptureInterface reports the selected packet capture interface at startup.
func (cfg *CaptureInterfaceConfig) LogCaptureInterface(log *logger.Logger) {
	if cfg.autoIfname != "" && cfg.autoIfname == cfg.Ifname {
		log.Warn().Str("ifname", cfg.Ifname).Str("selection", cfg.ifnameSelectionReason).
			Msgf("Automatically selected capture interface %q; only traffic on this interface is captured. Use '-i <interface>' or '--ifname <interface>' to change it.", cfg.Ifname)
		return
	}
	log.Info().Str("ifname", cfg.Ifname).
		Msg("Using specified capture interface; use '-i <interface>' or '--ifname <interface>' to change it")
}
