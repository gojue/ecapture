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
	"bytes"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/gojue/ecapture/internal/output/writers"

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

// packets of TC probe
type TcPacket struct {
	info gopacket.CaptureInfo
	data []byte
}

type NetCaptureData struct {
	PacketLength     uint32 `json:"pktLen"`
	ConfigIfaceIndex uint32 `json:"ifIndex"`
}

// PcapHandler handles packet events by writing them in PCAPNG format.
// PCAPNG (Packet Capture Next Generation) is the modern packet capture format
// that can be analyzed with Wireshark and other network analysis tools.
type PcapHandler struct {
	writer          writers.OutputWriter
	pcapWriter      *writers.PcapWriter
	mu              sync.Mutex
	masterKeyBuffer *bytes.Buffer
}

func (h *PcapHandler) Writer() writers.OutputWriter {
	return h.writer
}

// NewPcapHandler creates a new PcapHandler with the provided writer.
func NewPcapHandler(writer writers.OutputWriter) (*PcapHandler, error) {
	if writer == nil {
		return nil, errors.New(errors.ErrCodeResourceAllocation, "output writer cannot be nil")
	}

	// Create pcap writer with Ethernet link type and 65535 snaplen
	pcapWriter, err := writers.NewPcapWriter(writer, 65535, layers.LinkTypeEthernet)
	if err != nil {
		return nil, errors.Wrap(errors.ErrCodeResourceAllocation, "failed to create pcap writer", err)
	}

	return &PcapHandler{
		writer:          writer,
		pcapWriter:      pcapWriter,
		masterKeyBuffer: bytes.NewBuffer(nil),
	}, nil
}

// Handle processes a packet event and writes it to the pcapng file.
func (h *PcapHandler) Handle(event domain.Event) error {
	if event == nil {
		return nil // Silently ignore nil events
	}

	// Type assert to packet event
	pktEvent, ok := event.(PacketEvent)
	if !ok {
		// Not a packet event, skip silently (other handlers will process it)
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Get packet data
	packetData := pktEvent.GetPacketData()
	if len(packetData) == 0 {
		return nil // Empty packet, skip
	}

	// Convert timestamp from nanoseconds to time.Time
	timestamp := time.Unix(0, int64(pktEvent.GetTimestamp()))

	// Write packet to pcapng file
	err := h.pcapWriter.WritePacket(packetData, timestamp)
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write packet to pcapng", err)
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *PcapHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// First flush the pcap writer (NgWriter)
	if err := h.pcapWriter.Flush(); err != nil {
		return err
	}

	// Then close the pcap writer (NgWriter)
	if h.pcapWriter != nil {
		if err := h.pcapWriter.Close(); err != nil {
			return err
		}
	}

	// Finally close the underlying file writer
	if h.writer != nil {
		return h.writer.Close()
	}

	return nil
}

// Name returns the handler's identifier.
func (h *PcapHandler) Name() string {
	return ModePcapng
}

func (h *PcapHandler) PcapWriter() *writers.PcapWriter {
	return h.pcapWriter
}
