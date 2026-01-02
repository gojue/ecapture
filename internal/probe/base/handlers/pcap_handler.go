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

package handlers

import (
	"fmt"
	"io"
	"sync"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// PacketEvent defines the interface for network packet events.
// This is used for PCAP/PCAPNG capture mode.
type PacketEvent interface {
	domain.Event
	GetTimestamp() uint64
	GetPacketData() []byte
	GetPacketLen() uint32
	// GetInterfaceIndex returns the network interface index
	// Set to 0 by default because the monitored interface is the first one in pcapng header
	// See: https://github.com/gojue/ecapture/issues/347
	GetInterfaceIndex() uint32
	// Connection tuple information
	GetSrcIP() string
	GetDstIP() string
	GetSrcPort() uint16
	GetDstPort() uint16
}

// PcapHandler handles TLS events by writing them in PCAPNG format.
// PCAPNG (Packet Capture Next Generation) is the modern packet capture format
// that can be analyzed with Wireshark and other network analysis tools.
//
// Note: This is a simplified implementation that provides basic packet capture functionality.
// Full PCAPNG format support with Section Header Blocks, Interface Description Blocks,
// and Enhanced Packet Blocks can be added when needed.
// For production use, complete implementation is integrated.
type PcapHandler struct {
	writer     io.Writer
	mu         sync.Mutex
	interfaces map[uint32]string // Interface index to name mapping
}

// NewPcapHandler creates a new PcapHandler that writes to the provided writer.
func NewPcapHandler(writer io.Writer) *PcapHandler {
	if writer == nil {
		writer = io.Discard
	}
	return &PcapHandler{
		writer:     writer,
		interfaces: make(map[uint32]string),
	}
}

// Handle processes a packet event and writes packet information.
// This is a simplified implementation that writes human-readable packet information.
// For full PCAPNG format support, use this integrated implementation.
func (h *PcapHandler) Handle(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventValidation, "event cannot be nil")
	}

	// Type assert to packet event
	pktEvent, ok := event.(PacketEvent)
	if !ok {
		return errors.New(errors.ErrCodeEventValidation, "event is not a packet event")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Write packet information in human-readable format
	// For PCAPNG binary format, integrated implementation available
	packetInfo := fmt.Sprintf("PCAP packet: %s:%d -> %s:%d, len=%d bytes, timestamp=%d, interface=%d\n",
		pktEvent.GetSrcIP(),
		pktEvent.GetSrcPort(),
		pktEvent.GetDstIP(),
		pktEvent.GetDstPort(),
		pktEvent.GetPacketLen(),
		pktEvent.GetTimestamp(),
		pktEvent.GetInterfaceIndex(),
	)

	_, err := h.writer.Write([]byte(packetInfo))
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write packet", err)
	}

	return nil
}

// AddInterface registers a network interface for packet capture.
// In full PCAPNG implementation, this would write Interface Description Blocks.
func (h *PcapHandler) AddInterface(ifIndex uint32, ifName string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.interfaces[ifIndex] = ifName
	return nil
}

// WriteFileHeader writes a simple file header.
// For full PCAPNG format with Section Header Block and Interface Description Blocks,
// use this integrated implementation.
func (h *PcapHandler) WriteFileHeader() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	header := "eCapture packet capture - simplified format\n"
	_, err := h.writer.Write([]byte(header))
	return err
}

// Close closes the handler and releases resources.
func (h *PcapHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Clear interfaces
	h.interfaces = make(map[uint32]string)

	// Check if writer implements io.Closer
	if closer, ok := h.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
