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
// TODO: This is a Phase 4 Plan B stub implementation for PR #3.
// Full implementation will include:
// - Complete PCAPNG file format headers (Section Header Block, Interface Description Block)
// - Enhanced Packet Blocks with packet metadata
// - TC (Traffic Control) classifier integration for packet capture
// - Connection tracking and tuple management
// - Proper timestamp handling and interface mapping
type PcapHandler struct {
	writer     io.Writer
	mu         sync.Mutex
	interfaces map[uint32]string // Interface index to name mapping
	// TODO: Add in full implementation:
	// pcapngWriter *pcapng.Writer
	// sectionHeader *pcapng.SectionHeader
	// interfaceBlocks map[uint32]*pcapng.InterfaceBlock
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

// Handle processes a packet event and writes it in PCAPNG format.
// TODO: This is a stub implementation. Full implementation will:
// - Write proper PCAPNG Enhanced Packet Blocks
// - Include packet metadata (interface, timestamp, packet length)
// - Handle TLS decryption with master secrets
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

	// TODO: Implement PCAPNG format writing
	// For now, write a placeholder message
	placeholder := fmt.Sprintf("PCAP packet: %s:%d -> %s:%d, len=%d bytes (TODO: PCAPNG format)\n",
		pktEvent.GetSrcIP(),
		pktEvent.GetSrcPort(),
		pktEvent.GetDstIP(),
		pktEvent.GetDstPort(),
		pktEvent.GetPacketLen(),
	)

	_, err := h.writer.Write([]byte(placeholder))
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write packet", err)
	}

	return nil
}

// AddInterface registers a network interface for PCAPNG output.
// TODO: Full implementation will create Interface Description Blocks.
func (h *PcapHandler) AddInterface(ifIndex uint32, ifName string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.interfaces[ifIndex] = ifName
	// TODO: Write Interface Description Block to PCAPNG file
	return nil
}

// WriteFileHeader writes the PCAPNG file header.
// TODO: Full implementation will write Section Header Block and Interface Description Blocks.
func (h *PcapHandler) WriteFileHeader() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// TODO: Write PCAPNG Section Header Block
	// For now, write a placeholder
	placeholder := "PCAPNG file header (TODO: implement Section Header Block)\n"
	_, err := h.writer.Write([]byte(placeholder))
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
