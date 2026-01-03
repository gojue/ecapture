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
	// Use pcapgo.DSB_SECRETS_TYPE_TLS for TLS key logs
	return pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, []byte(keylogLine))
}

// Flush ensures all buffered data is written to disk
func (pw *PcapWriter) Flush() error {
	// Flush the underlying writer if it supports flushing
	type flusher interface {
		Flush() error
	}
	if f, ok := interface{}(pw.writer).(flusher); ok {
		return f.Flush()
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
	if closer, ok := interface{}(pw.writer).(io.Closer); ok {
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
