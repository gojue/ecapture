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
	stderrors "errors"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output/pcapng"
	"github.com/gojue/ecapture/v2/internal/output/writers"
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

type Option func(*PcapngHandler) error

// WithInterfaceName sets the network interface name for the pcapng session.
func WithInterfaceName(ifName string) Option {
	return func(h *PcapngHandler) error {
		h.ifName = ifName
		return nil
	}
}

// WithFilter sets the BPF filter for the pcapng session.
func WithFilter(filter string) Option {
	return func(h *PcapngHandler) error {
		h.filter = filter
		return nil
	}
}

// WithLogger sets the logger for the PcapngHandler (currently unused, but can be used for future logging enhancements).
func WithLogger(logger *logger.Logger) Option {
	return func(h *PcapngHandler) error {
		// Currently no logger is used in PcapngHandler, but we can add logging in the future if needed.
		h.logger = logger
		return nil
	}
}

// PcapngHandler handles packet events by writing them in PCAPNG format.
// PCAPNG (Packet Capture Next Generation) is the modern packet capture format
// that can be analyzed with Wireshark and other network analysis tools.
type PcapngHandler struct {
	sink            writers.ByteSink
	session         *pcapng.Session
	mu              sync.Mutex
	masterKeyBuffer *bytes.Buffer
	ifName          string
	filter          string
	logger          *logger.Logger
	closed          bool
	closeErr        error
}

func (h *PcapngHandler) Writer() writers.OutputWriter {
	return h.sink
}

func (h *PcapngHandler) Supports(event domain.Event) bool {
	return isPacketEvent(event)
}

func isPacketEvent(event domain.Event) bool {
	if event == nil {
		return false
	}
	_, ok := event.(PacketEvent)
	return ok
}

// NewPcapngHandler creates a new PcapngHandler with the provided byte sink.
func NewPcapngHandler(sink writers.ByteSink, ifName, filter string, lger *logger.Logger) (*PcapngHandler, error) {
	if sink == nil {
		return nil, errors.New(errors.ErrCodeResourceAllocation, "pcapng sink cannot be nil")
	}

	// Create a pcapng session with Ethernet link type and 65535 snaplen.
	session, err := pcapng.NewSession(sink, 65535, ifName, filter, lger)
	if err != nil {
		return nil, errors.Wrap(errors.ErrCodeResourceAllocation, "failed to create pcapng session", err)
	}

	return &PcapngHandler{
		sink:            sink,
		session:         session,
		masterKeyBuffer: bytes.NewBuffer(nil),
		logger:          lger,
	}, nil
}

// Handle processes a packet event and writes it to the pcapng file.
func (h *PcapngHandler) Handle(event domain.Event) error {
	if !h.Supports(event) {
		return errors.New(errors.ErrCodeEventDispatch, "pcapng handler does not support event")
	}
	pktEvent := event.(PacketEvent)

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New(errors.ErrCodeEventDispatch, "pcapng handler is closed")
	}

	// Get packet data
	packetData := pktEvent.GetPacketData()
	if len(packetData) == 0 {
		h.logger.Debug().Msg("packet data is empty")
		return nil // Empty packet, skip
	}

	// Convert timestamp from nanoseconds to time.Time
	timestamp := time.Unix(0, int64(pktEvent.GetTimestamp()))

	// Write packet to pcapng file
	err := h.session.WritePacket(packetData, timestamp)
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write packet to pcapng", err)
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *PcapngHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return h.closeErr
	}
	h.closed = true

	var closeErrors []error
	if h.session != nil {
		closeErrors = append(closeErrors, h.session.Close())
	}
	if h.sink != nil {
		closeErrors = append(closeErrors, h.sink.Flush(), h.sink.Close())
	}
	h.closeErr = stderrors.Join(closeErrors...)
	return h.closeErr
}

// Name returns the handler's identifier.
func (h *PcapngHandler) Name() string {
	return ModePcapng
}

func (h *PcapngHandler) Session() *pcapng.Session {
	return h.session
}
