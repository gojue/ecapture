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

package handlers

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PcapWriter handles writing network packets in PCAPNG format
type PcapWriter struct {
	writer   *pcapgo.NgWriter
	ifaceIdx int
}

// NewPcapWriter creates a new PCAPNG writer
func NewPcapWriter(w io.Writer, snaplen uint32, linkType layers.LinkType) (*PcapWriter, error) {
	ngWriter, err := pcapgo.NewNgWriter(w, linkType)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcapng writer: %w", err)
	}

	// Add interface to PCAPNG file
	iface := pcapgo.NgInterface{
		Name:       "eCapture(旁观者)",
		Comment:    "eCapture GoTLS capture interface",
		Filter:     "",
		LinkType:   linkType,
		SnapLength: snaplen,
	}

	ifaceIdx, err := ngWriter.AddInterface(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to add interface to pcapng: %w", err)
	}

	return &PcapWriter{
		writer:   ngWriter,
		ifaceIdx: ifaceIdx,
	}, nil
}

// WritePacket writes a packet to the PCAPNG file
func (pw *PcapWriter) WritePacket(data []byte, timestamp time.Time) error {
	captureInfo := gopacket.CaptureInfo{
		Timestamp:      timestamp,
		CaptureLength:  len(data),
		Length:         len(data),
		InterfaceIndex: pw.ifaceIdx,
	}

	return pw.writer.WritePacket(captureInfo, data)
}

// WriteMasterSecret writes TLS master secret as a Decryption Secrets Block (DSB)
func (pw *PcapWriter) WriteMasterSecret(label, clientRandom, secret []byte) error {
	// Format: "LABEL CLIENTRANDOM SECRET\n"
	// This follows the NSS SSLKEYLOGFILE format
	keylogLine := fmt.Sprintf("%s %x %x\n", 
		nullTerminatedString(label),
		clientRandom,
		secret)

	// Write as DSB (Decryption Secrets Block) using custom gopacket implementation
	// The cfc4n/gopacket fork includes WriteDecryptionSecretsBlock method
	return pw.writer.WriteDecryptionSecretsBlock([]byte(keylogLine))
}

// Flush ensures all buffered data is written to disk
func (pw *PcapWriter) Flush() error {
	// Flush the underlying writer if it supports flushing
	if flusher, ok := pw.writer.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// Close closes the PCAPNG writer and flushes any buffered data
// This should be called when the program exits to ensure all data is written
func (pw *PcapWriter) Close() error {
	// Flush any remaining data before closing
	if err := pw.Flush(); err != nil {
		return err
	}
	
	// Close the writer if it implements io.Closer
	if closer, ok := pw.writer.(io.Closer); ok {
		return closer.Close()
	}
	
	return nil
}

// nullTerminatedString returns the string up to the first null byte
func nullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// PacketEvent represents a network packet event from TC eBPF probes
type PacketEvent struct {
	Timestamp      uint64
	InterfaceIndex uint32
	PacketLen      uint32
	PacketData     []byte
	SrcIP          [16]byte
	DstIP          [16]byte
	SrcPort        uint16
	DstPort        uint16
	IsIPv6         bool
}

// DecodeFromBytes decodes packet event from raw bytes
func (pe *PacketEvent) DecodeFromBytes(data []byte) error {
	if len(data) < 56 { // Minimum size for the event structure
		return fmt.Errorf("packet event data too small: %d bytes", len(data))
	}

	pe.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	pe.InterfaceIndex = binary.LittleEndian.Uint32(data[8:12])
	pe.PacketLen = binary.LittleEndian.Uint32(data[12:16])
	
	// Copy IP addresses
	copy(pe.SrcIP[:], data[16:32])
	copy(pe.DstIP[:], data[32:48])
	
	pe.SrcPort = binary.LittleEndian.Uint16(data[48:50])
	pe.DstPort = binary.LittleEndian.Uint16(data[50:52])
	
	if len(data) > 52 {
		pe.IsIPv6 = data[52] != 0
	}
	
	// Packet data follows the header
	if len(data) > 56 {
		pe.PacketData = data[56:]
	}

	return nil
}

// GetTimestamp implements domain.Event interface
func (pe *PacketEvent) GetTimestamp() uint64 {
	return pe.Timestamp
}

// GetPacketData returns the packet payload
func (pe *PacketEvent) GetPacketData() []byte {
	return pe.PacketData
}

// GetPacketLen returns the packet length
func (pe *PacketEvent) GetPacketLen() uint32 {
	return pe.PacketLen
}

// GetInterfaceIndex returns the interface index
func (pe *PacketEvent) GetInterfaceIndex() uint32 {
	return pe.InterfaceIndex
}

// String returns a string representation of the event
func (pe *PacketEvent) String() string {
	return fmt.Sprintf("PacketEvent{ts=%d, iface=%d, len=%d, %s:%d -> %s:%d}",
		pe.Timestamp, pe.InterfaceIndex, pe.PacketLen,
		pe.GetSrcIP(), pe.SrcPort,
		pe.GetDstIP(), pe.DstPort)
}

// GetSrcIP returns source IP as string
func (pe *PacketEvent) GetSrcIP() string {
	if pe.IsIPv6 {
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			binary.BigEndian.Uint16(pe.SrcIP[0:2]),
			binary.BigEndian.Uint16(pe.SrcIP[2:4]),
			binary.BigEndian.Uint16(pe.SrcIP[4:6]),
			binary.BigEndian.Uint16(pe.SrcIP[6:8]),
			binary.BigEndian.Uint16(pe.SrcIP[8:10]),
			binary.BigEndian.Uint16(pe.SrcIP[10:12]),
			binary.BigEndian.Uint16(pe.SrcIP[12:14]),
			binary.BigEndian.Uint16(pe.SrcIP[14:16]))
	}
	return fmt.Sprintf("%d.%d.%d.%d", pe.SrcIP[0], pe.SrcIP[1], pe.SrcIP[2], pe.SrcIP[3])
}

// GetDstIP returns destination IP as string
func (pe *PacketEvent) GetDstIP() string {
	if pe.IsIPv6 {
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			binary.BigEndian.Uint16(pe.DstIP[0:2]),
			binary.BigEndian.Uint16(pe.DstIP[2:4]),
			binary.BigEndian.Uint16(pe.DstIP[4:6]),
			binary.BigEndian.Uint16(pe.DstIP[6:8]),
			binary.BigEndian.Uint16(pe.DstIP[8:10]),
			binary.BigEndian.Uint16(pe.DstIP[10:12]),
			binary.BigEndian.Uint16(pe.DstIP[12:14]),
			binary.BigEndian.Uint16(pe.DstIP[14:16]))
	}
	return fmt.Sprintf("%d.%d.%d.%d", pe.DstIP[0], pe.DstIP[1], pe.DstIP[2], pe.DstIP[3])
}

// GetSrcPort returns source port
func (pe *PacketEvent) GetSrcPort() uint16 {
	return pe.SrcPort
}

// GetDstPort returns destination port
func (pe *PacketEvent) GetDstPort() uint16 {
	return pe.DstPort
}
