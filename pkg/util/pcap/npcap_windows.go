//go:build windows
// +build windows

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

package pcap

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/logger"
)

// Capture delivers raw network packets from an Npcap/WinPcap device.
type Capture struct {
	mu         sync.Mutex
	handle     *pcap.Handle
	ifName     string
	filter     string
	snaplen    int
	running    atomic.Bool
	stopCh     chan struct{}
	wg         sync.WaitGroup
	dispatcher domain.EventDispatcher
	logger     *logger.Logger
}

// Config holds configuration for a packet capture device.
type Config struct {
	IfName     string
	Filter     string
	Snaplen    int
	Dispatcher domain.EventDispatcher
	Logger     *logger.Logger
}

// NewCapture creates a new Npcap capture instance.
func NewCapture(cfg Config) (*Capture, error) {
	if cfg.IfName == "" {
		return nil, errors.New(errors.ErrCodeConfiguration, "interface name is required")
	}
	if cfg.Dispatcher == nil {
		return nil, errors.New(errors.ErrCodeConfiguration, "dispatcher is required")
	}
	if cfg.Snaplen == 0 {
		cfg.Snaplen = 65535
	}
	return &Capture{
		ifName:     cfg.IfName,
		filter:     cfg.Filter,
		snaplen:    cfg.Snaplen,
		dispatcher: cfg.Dispatcher,
		logger:     cfg.Logger,
		stopCh:     make(chan struct{}),
	}, nil
}

// Start opens the capture device and begins reading packets.
func (c *Capture) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running.Load() {
		return errors.New(errors.ErrCodeProbeStart, "capture already running")
	}

	handle, err := pcap.OpenLive(c.ifName, int32(c.snaplen), true, pcap.BlockForever)
	if err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "open interface", err).WithContext("interface", c.ifName)
	}

	if c.filter != "" {
		if err := handle.SetBPFFilter(c.filter); err != nil {
			handle.Close()
			return errors.Wrap(errors.ErrCodeProbeStart, "set BPF filter", err).WithContext("filter", c.filter)
		}
	}

	c.handle = handle
	c.running.Store(true)
	c.stopCh = make(chan struct{})
	c.wg.Add(1)
	go c.readLoop()

	if c.logger != nil {
		c.logger.Info().Str("interface", c.ifName).Str("filter", c.filter).Msg("Npcap capture started")
	}
	return nil
}

// Stop closes the capture handle and waits for the read loop to exit.
func (c *Capture) Stop() error {
	c.mu.Lock()
	if !c.running.Load() {
		c.mu.Unlock()
		return nil
	}
	c.running.Store(false)
	close(c.stopCh)
	handle := c.handle
	c.handle = nil
	c.mu.Unlock()

	if handle != nil {
		// Closing the handle unblocks the read loop.
		handle.Close()
	}
	c.wg.Wait()
	return nil
}

// IsRunning returns whether the capture is active.
func (c *Capture) IsRunning() bool {
	return c.running.Load()
}

func (c *Capture) readLoop() {
	defer c.wg.Done()

	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	for {
		select {
		case <-c.stopCh:
			return
		case packet, ok := <-src.Packets():
			if !ok {
				return
			}
			c.dispatchPacket(packet)
		}
	}
}

// waitForFirstPacket blocks until a packet arrives or the timeout elapses.
func (c *Capture) waitForFirstPacket(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if stats, err := c.handle.Stats(); err == nil && stats.PacketsReceived > 0 {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func (c *Capture) dispatchPacket(packet gopacket.Packet) {
	ci := packet.Metadata().CaptureInfo
	ev := &PacketEvent{
		Timestamp: uint64(ci.Timestamp.UnixNano()),
		Data:      packet.Data(),
		Length:    uint32(len(packet.Data())),
		IfIndex:   0,
	}

	// Try to populate layer-3/layer-4 tuple information.
	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ipv4 := ip4.(*layers.IPv4)
		ev.SrcIP = ipv4.SrcIP.String()
		ev.DstIP = ipv4.DstIP.String()
		if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			t := tcp.(*layers.TCP)
			ev.SrcPort = uint16(t.SrcPort)
			ev.DstPort = uint16(t.DstPort)
		}
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ipv6 := ip6.(*layers.IPv6)
		ev.SrcIP = ipv6.SrcIP.String()
		ev.DstIP = ipv6.DstIP.String()
		if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			t := tcp.(*layers.TCP)
			ev.SrcPort = uint16(t.SrcPort)
			ev.DstPort = uint16(t.DstPort)
		}
	}

	if err := c.dispatcher.Dispatch(ev); err != nil && c.logger != nil {
		c.logger.Warn().Err(err).Msg("Failed to dispatch packet event")
	}
}

// FindInterface returns the first active non-loopback interface name, or an
// empty string if none is found.
func FindInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			return iface.Name
		}
	}
	return ""
}

// PacketEvent implements handlers.PacketEvent for packets captured via Npcap.
type PacketEvent struct {
	Timestamp uint64
	Data      []byte
	Length    uint32
	IfIndex   uint32
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
}

func (e *PacketEvent) DecodeFromBytes(data []byte) error { e.Data = data; return nil }
func (e *PacketEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (e *PacketEvent) Validate() error                   { return nil }
func (e *PacketEvent) StringHex() string                 { return fmt.Sprintf("%x", e.Data) }
func (e *PacketEvent) UUID() string {
	return fmt.Sprintf("pkt-%d-%s:%d-%s:%d", e.Timestamp, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
}
func (e *PacketEvent) String() string {
	return fmt.Sprintf("PACKET %s:%d -> %s:%d len=%d", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Length)
}
func (e *PacketEvent) Clone() domain.Event {
	c := &PacketEvent{
		Timestamp: e.Timestamp,
		Length:    e.Length,
		IfIndex:   e.IfIndex,
		SrcIP:     e.SrcIP,
		DstIP:     e.DstIP,
		SrcPort:   e.SrcPort,
		DstPort:   e.DstPort,
	}
	if e.Data != nil {
		c.Data = make([]byte, len(e.Data))
		copy(c.Data, e.Data)
	}
	return c
}
func (e *PacketEvent) GetTimestamp() uint64      { return e.Timestamp }
func (e *PacketEvent) GetPacketData() []byte     { return e.Data }
func (e *PacketEvent) GetPacketLen() uint32      { return e.Length }
func (e *PacketEvent) GetInterfaceIndex() uint32 { return e.IfIndex }
func (e *PacketEvent) GetSrcIP() string          { return e.SrcIP }
func (e *PacketEvent) GetDstIP() string          { return e.DstIP }
func (e *PacketEvent) GetSrcPort() uint16        { return e.SrcPort }
func (e *PacketEvent) GetDstPort() uint16        { return e.DstPort }
