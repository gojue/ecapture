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
	"io"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/gojue/ecapture/v2/internal/errors"
	lger "github.com/gojue/ecapture/v2/internal/logger"
)

type TcPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

const (
	pcapFlushInterval = 2 * time.Second
	dsbGracePeriod    = 3 * time.Second
)

// PcapWriter handles writing network packets in PCAPNG format
type PcapWriter struct {
	writer    *pcapgo.NgWriter
	ifaceIdx  int
	ctx       context.Context
	ctxCancel context.CancelFunc

	tcPackets []*TcPacket

	// WritePacket must not discard a burst merely because Serve is flushing the
	// previous batch to disk. Keep a short critical section in the perf-reader
	// path and wake Serve through a coalescing notification instead of using a
	// bounded packet channel.
	queueMu        sync.Mutex
	pendingPackets []*TcPacket
	pendingKeylogs [][]byte
	queueReady     chan struct{}
	stopped        bool

	serveDone   chan struct{}
	packetCount int
	closeMu     sync.Mutex
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
		queueReady: make(chan struct{}, 1),
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

	pw.queueMu.Lock()
	if pw.stopped {
		pw.queueMu.Unlock()
		return errors.New(errors.ErrCodeEventDispatch, "pcap writer is closed")
	}
	pw.pendingPackets = append(pw.pendingPackets, &TcPacket{ci: captureInfo, data: data})
	pw.queueMu.Unlock()

	// One notification is sufficient: Serve drains the complete pending queue.
	select {
	case pw.queueReady <- struct{}{}:
	default:
	}
	return nil
}

func (pw *PcapWriter) takePendingData() ([]*TcPacket, [][]byte) {
	pw.queueMu.Lock()
	defer pw.queueMu.Unlock()

	packets := pw.pendingPackets
	keylogs := pw.pendingKeylogs
	pw.pendingPackets = nil
	pw.pendingKeylogs = nil
	return packets, keylogs
}

func (pw *PcapWriter) takePendingKeylogs() [][]byte {
	pw.queueMu.Lock()
	defer pw.queueMu.Unlock()

	keylogs := pw.pendingKeylogs
	pw.pendingKeylogs = nil
	return keylogs
}

func (pw *PcapWriter) writeQueuedKeylogs(keylogs [][]byte) {
	if len(keylogs) == 0 {
		return
	}
	for _, keylogLine := range keylogs {
		if e := pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylogLine); e != nil {
			pw.logger.Warn().Err(e).Msg("failed to write queued DSB to pcapng")
		}
	}
	if e := pw.writer.Flush(); e != nil {
		pw.logger.Warn().Err(e).Msg("failed to flush after DSB write")
	}
}

// savePacketBatch writes secrets that are already queued before writing the
// buffered packet batch. The timer and queue notification can become ready at
// the same time, so the timer cannot rely on the notification being selected
// first to preserve pcapng's sequential DSB-before-packet ordering.
func (pw *PcapWriter) savePacketBatch() (int, error) {
	pw.writeQueuedKeylogs(pw.takePendingKeylogs())
	return pw.savePcapng()
}

// Serve processes queued packets and keylogs and writes them to the PCAPNG writer.
// All NgWriter operations are serialized in this single goroutine to avoid concurrent access.
func (pw *PcapWriter) Serve() {
	pw.serve(pcapFlushInterval, dsbGracePeriod)
}

func (pw *PcapWriter) serve(flushInterval, gracePeriod time.Duration) {
	defer close(pw.serveDone)

	ti := time.NewTicker(flushInterval)
	defer ti.Stop()

	// Hold each newly buffered packet batch for a short grace period so every DSB emitted
	// by the handshake is written first. Wireshark processes blocks sequentially;
	// the application traffic secrets must precede the encrypted packet blocks.
	var dsbGraceDeadline time.Time

	var i int
	for {
		select {
		case <-ti.C:
			if i == 0 || len(pw.tcPackets) == 0 {
				continue
			}
			// Always hold each packet batch for the full grace period. A
			// TLS 1.3 handshake emits multiple DSB entries, so seeing the first
			// one does not mean the traffic-secret set is complete.
			if time.Now().Before(dsbGraceDeadline) {
				continue
			}
			n, e := pw.savePacketBatch()
			if e != nil {
				pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err, maybe some packets lost.")
			} else {
				pw.packetCount += n
			}

			// reset counter, and reset tcPackets array
			i = 0
			pw.tcPackets = pw.tcPackets[:0]
			dsbGraceDeadline = time.Time{}
		case <-pw.queueReady:
			packets, keylogs := pw.takePendingData()
			pw.writeQueuedKeylogs(keylogs)
			if len(packets) == 0 {
				continue
			}
			if dsbGraceDeadline.IsZero() {
				dsbGraceDeadline = time.Now().Add(gracePeriod)
			}
			pw.tcPackets = append(pw.tcPackets, packets...)
			i += len(packets)
		case <-pw.ctx.Done():
			// Context canceled — drain all remaining queued data before exiting.
			pw.drainOnShutdown()
			return
		}
	}
}

// drainOnShutdown drains remaining queued packets and keylogs and writes
// them to the PCAPNG file. Called only from Serve() on context cancellation.
// DSBs are written before packets to ensure Wireshark can decrypt the traffic.
func (pw *PcapWriter) drainOnShutdown() {
	// Move remaining queued data into the output batch. Write DSBs first so
	// Wireshark sees every secret before the corresponding packet blocks.
	packets, keylogs := pw.takePendingData()
	pw.tcPackets = append(pw.tcPackets, packets...)
	for _, keylog := range keylogs {
		if e := pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); e != nil {
			pw.logger.Warn().Err(e).Msg("failed to write DSB on shutdown")
		}
	}

	// Now save all buffered packets (after DSBs)
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

	// Final flush after draining all data
	if e := pw.writer.Flush(); e != nil {
		pw.logger.Warn().Err(e).Msg("failed to flush on shutdown")
	}
}

// savePcapng writes all buffered packets and flushes the writer
func (pw *PcapWriter) savePcapng() (i int, err error) {
	// TC events can arrive from different per-CPU perf buffers out of timestamp
	// order. Preserve capture chronology so TCP/TLS reassembly does not see a
	// later segment before the data that precedes it.
	sort.SliceStable(pw.tcPackets, func(i, j int) bool {
		return pw.tcPackets[i].ci.Timestamp.Before(pw.tcPackets[j].ci.Timestamp)
	})
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

	pw.queueMu.Lock()
	if pw.stopped {
		pw.queueMu.Unlock()
		return errors.New(errors.ErrCodeEventDispatch, "pcap writer is closed")
	}
	pw.pendingKeylogs = append(pw.pendingKeylogs, data)
	pw.queueMu.Unlock()

	select {
	case pw.queueReady <- struct{}{}:
	default:
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
	pw.closeMu.Lock()
	defer pw.closeMu.Unlock()

	if pw.isClosed {
		return nil
	}
	defer func() {
		pw.isClosed = true
	}()

	// Stop accepting packets before the final queue drain. This prevents a
	// producer from appending after Serve has exited.
	pw.queueMu.Lock()
	pw.stopped = true
	pw.queueMu.Unlock()

	// Stop the Serve goroutine by canceling its context.
	// The Serve goroutine will flush remaining packets before exiting.
	pw.ctxCancel()

	// Wait for the Serve goroutine to finish all pending writes.
	// This ensures no concurrent access to the NgWriter after this point.
	<-pw.serveDone

	// Final flush to ensure all data is written to the underlying writer
	if err := pw.Flush(); err != nil {
		return err
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
