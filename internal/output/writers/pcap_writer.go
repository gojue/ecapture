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

package writers

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/gojue/ecapture/internal/errors"
	lger "github.com/gojue/ecapture/internal/logger"
)

type TcPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

// PcapWriter handles writing network packets in PCAPNG format
type PcapWriter struct {
	writer    *pcapgo.NgWriter
	ifaceIdx  int
	ctx       context.Context
	ctxCancel context.CancelFunc

	tcPackets   []*TcPacket
	packetChan  chan *TcPacket
	keylogChan  chan []byte // channel for DSB (keylog) writes, serialized with packet writes
	serveDone   chan struct{}
	packetCount int
	isClosed    bool
	logger      *lger.Logger
}

// NewPcapWriter creates a new PCAPNG writer
func NewPcapWriter(w io.Writer, snaplen uint32, ifName, filter string, logger *lger.Logger) (*PcapWriter, error) {
	// create pcapng writer
	netIfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// TODO : write Application "ecapture.lua" to decode PID/Comm info.
	pcapOption := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    "eCapture (旁观者) Hardware",
			OS:          "Linux/Android",
			Application: "ecapture.lua",
			Comment:     "see https://ecapture.cc for more information. CFC4N <cfc4n.cs@gmail.com>",
		},
	}
	// write interface description
	ngIface := pcapgo.NgInterface{
		Name:       ifName,
		Comment:    "eCapture (旁观者): github.com/gojue/ecapture",
		Filter:     filter,
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: snaplen,
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(w, ngIface, pcapOption)
	if err != nil {
		return nil, err
	}

	var ifaceIdx int
	var lastIfaceIdx int
	// insert other interfaces into pcapng file
	for _, iface := range netIfs {
		ngIface = pcapgo.NgInterface{
			Name:       iface.Name,
			Comment:    "eCapture (旁观者): github.com/gojue/ecapture",
			Filter:     "",
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		}

		ifIdx, err := pcapWriter.AddInterface(ngIface)
		if err != nil {
			return nil, err
		}
		lastIfaceIdx = ifIdx
		if iface.Name == ifName {
			// found the interface index
			ifaceIdx = ifIdx
		}
	}

	// Flush the header
	err = pcapWriter.Flush()
	if err != nil {
		return nil, err
	}

	if ifaceIdx == 0 {
		// if not found, use the last interface index
		ifaceIdx = lastIfaceIdx
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &PcapWriter{
		writer:     pcapWriter,
		ifaceIdx:   ifaceIdx,
		packetChan: make(chan *TcPacket, 1024),
		keylogChan: make(chan []byte, 256),
		serveDone:  make(chan struct{}),
		ctx:        ctx,
		ctxCancel:  cancel,
		tcPackets:  []*TcPacket{},
		isClosed:   false,
		logger:     logger,
	}
	go pw.Serve()
	return pw, nil
}

// WritePacket writes a packet to the PCAPNG file
func (pw *PcapWriter) WritePacket(data []byte, timestamp time.Time) error {
	captureInfo := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data),
		//InterfaceIndex: pw.ifaceIdx,
		// set 0 default, Because the monitored network interface is the first one written into the pcapng header.
		// 设置为0，因为被监听的网卡是第一个写入pcapng header中的。
		// via : https://github.com/gojue/ecapture/issues/347
		InterfaceIndex: 0,
	}

	select {
	case pw.packetChan <- &TcPacket{ci: captureInfo, data: data}:
	default:
		// If the channel is full, write directly (blocking)
		return fmt.Errorf("pcap write packet channel full")
	}
	return nil
}

// Serve processes packets and keylogs from channels and writes them to the PCAPNG writer.
// All NgWriter operations are serialized in this single goroutine to avoid concurrent access.
func (pw *PcapWriter) Serve() {
	defer close(pw.serveDone)

	ti := time.NewTicker(2 * time.Second)
	defer ti.Stop()

	var i int
	for {
		select {
		case <-ti.C:
			if i == 0 || len(pw.tcPackets) == 0 {
				continue
			}
			n, e := pw.savePcapng()
			if e != nil {
				pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err, maybe some packets lost.")
			} else {
				pw.packetCount += n
			}

			// reset counter, and reset tcPackets array
			i = 0
			pw.tcPackets = pw.tcPackets[:0]
		case packet, ok := <-pw.packetChan:
			if !ok {
				// Channel closed — drain any remaining packets and exit
				if len(pw.tcPackets) > 0 {
					n, e := pw.savePcapng()
					if e != nil {
						pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err on close, maybe some packets lost.")
					} else {
						pw.packetCount += n
					}
				}
				return
			}
			pw.tcPackets = append(pw.tcPackets, packet)
			i++
		case keylogLine, ok := <-pw.keylogChan:
			if !ok {
				// Channel closed — nil out to remove from select, preventing CPU spin.
				// (Receiving from a closed channel returns zero value immediately.)
				pw.keylogChan = nil
				continue
			}
			// Flush any pending packets before writing DSB to maintain correct block order
			if len(pw.tcPackets) > 0 {
				n, e := pw.savePcapng()
				if e != nil {
					pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err before DSB, maybe some packets lost.")
				} else {
					pw.packetCount += n
				}
				i = 0
				pw.tcPackets = pw.tcPackets[:0]
			}
			// Write DSB (Decryption Secrets Block) - all NgWriter access in this goroutine
			if e := pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylogLine); e != nil {
				pw.logger.Warn().Err(e).Msg("failed to write DSB to pcapng")
			}
			if e := pw.writer.Flush(); e != nil {
				pw.logger.Warn().Err(e).Msg("failed to flush after DSB write")
			}
		case <-pw.ctx.Done():
			// Context canceled — drain all remaining data from channels before exiting
			pw.drainOnShutdown()
			return
		}
	}
}

// drainOnShutdown drains remaining packets and keylogs from channels and writes
// them to the PCAPNG file. Called only from Serve() on context cancellation.
func (pw *PcapWriter) drainOnShutdown() {
	// Drain remaining packets from packetChan
drainPackets:
	for {
		select {
		case packet, ok := <-pw.packetChan:
			if !ok {
				break drainPackets
			}
			pw.tcPackets = append(pw.tcPackets, packet)
		default:
			break drainPackets
		}
	}

	// Save all buffered packets
	if len(pw.tcPackets) > 0 {
		n, e := pw.savePcapng()
		if e != nil {
			pw.logger.Info().Err(e).Msg("save pcapng err on shutdown, maybe some packets lost.")
		} else {
			pw.logger.Info().Int("count", n).Msg("packets saved into pcapng file on shutdown.")
			pw.packetCount += n
		}
		pw.tcPackets = pw.tcPackets[:0]
	}

	// Drain remaining keylogs from keylogChan
drainKeylogs:
	for {
		select {
		case keylog, ok := <-pw.keylogChan:
			if !ok {
				break drainKeylogs
			}
			if e := pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); e != nil {
				pw.logger.Warn().Err(e).Msg("failed to write DSB on shutdown")
			}
		default:
			break drainKeylogs
		}
	}

	// Final flush after draining all data
	if e := pw.writer.Flush(); e != nil {
		pw.logger.Warn().Err(e).Msg("failed to flush on shutdown")
	}
}

// savePcapng writes all buffered packets and flushes the writer
func (pw *PcapWriter) savePcapng() (i int, err error) {
	for _, packet := range pw.tcPackets {
		err = pw.writer.WritePacket(packet.ci, packet.data)
		i++
		if err != nil {
			return
		}
	}

	if i == 0 {
		return
	}
	err = pw.writer.Flush()
	return
}

// writePacket writes a single packet to the PCAPNG writer
func (pw *PcapWriter) writePacket(pc *TcPacket) error {
	return pw.writer.WritePacket(pc.ci, pc.data)
}

// WriteKeyLog writes TLS master secret as a Decryption Secrets Block (DSB).
// The actual write is serialized through the Serve goroutine to avoid concurrent
// access to the underlying NgWriter (which is not thread-safe).
func (pw *PcapWriter) WriteKeyLog(keylogLine []byte) error {
	// Make a copy to avoid the caller modifying the data after sending
	data := make([]byte, len(keylogLine))
	copy(data, keylogLine)

	select {
	case pw.keylogChan <- data:
	default:
		return fmt.Errorf("keylog write channel full")
	}
	return nil
}

// Flush ensures all buffered data is written to disk.
// While the Serve goroutine is running, all NgWriter operations are serialized there
// and flushing happens automatically (on timer ticks, DSB writes, and shutdown).
// Direct flush is only performed after Serve has exited to avoid concurrent access.
func (pw *PcapWriter) Flush() error {
	select {
	case <-pw.serveDone:
		// Serve has exited — safe to flush directly
		return pw.writer.Flush()
	default:
		// Serve is still running — it handles flushing internally
		return nil
	}
}

// Close closes the PCAPNG writer and flushes any buffered data.
// This should be called when the program exits to ensure all data is written.
func (pw *PcapWriter) Close() error {
	if pw.isClosed {
		return nil
	}
	defer func() {
		pw.isClosed = true
	}()

	// Stop the Serve goroutine by canceling its context.
	// The Serve goroutine will flush remaining packets before exiting.
	pw.ctxCancel()

	// Wait for the Serve goroutine to finish all pending writes.
	// This ensures no concurrent access to the NgWriter after this point.
	<-pw.serveDone

	// Close channels so they don't leak (Serve has already exited).
	close(pw.packetChan)
	close(pw.keylogChan)

	// Final flush to ensure all data is written to the underlying writer
	if err := pw.Flush(); err != nil {
		return err
	}

	// Close the writer if it implements io.Closer
	if closer, ok := any(pw.writer).(io.Closer); ok {
		return closer.Close()
	}

	if pw.packetCount == 0 {
		return errors.Wrap(errors.ErrCodeEventNotReady, "nothing captured, please check your network interface, see \"ecapture tls -h\" for more information.", nil)
	}

	return nil
}

func (pw *PcapWriter) Name() string {
	return "pcap_writer"
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
