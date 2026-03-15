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
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
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

	tcPackets       []*TcPacket
	masterKeyBuffer *bytes.Buffer
	tcPacketLocker  *sync.Mutex
	packetChan      chan *TcPacket
	packetCount     int
	isClosed        bool
	logger          *lger.Logger
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

// Serve processes packets from the channel and writes them to the PCAPNG writer
func (pw *PcapWriter) Serve() {
	ti := time.NewTicker(2 * time.Second)
	defer func() {
		ti.Stop()
	}()

	var i int
	for {
		select {
		case _ = <-ti.C:
			if i == 0 || len(pw.tcPackets) == 0 {
				continue
			}
			n, e := pw.savePcapng()
			if e != nil {
				pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err, maybe some packets lost.")
			} else {
				//t.logger.Info().Int("count", n).Msg("packets saved into pcapng file.")
				pw.packetCount += n
			}

			// reset counter, and reset tcPackets array
			i = 0
			pw.tcPackets = pw.tcPackets[:0]
		case packet, ok := <-pw.packetChan:
			// append tcPackets to tcPackets Array from tcPacketsChan
			if !ok {
				return
			}
			pw.tcPackets = append(pw.tcPackets, packet)
			i++
		case _ = <-pw.ctx.Done():
			if i == 0 || len(pw.tcPackets) == 0 {
				return
			}
			n, e := pw.savePcapng()
			if e != nil {
				pw.logger.Info().Err(e).Int("count", i).Msg("save pcapng err, maybe some packets lost.")
			} else {
				pw.logger.Info().Int("count", n).Msg("packets saved into pcapng file.")
				pw.packetCount += n
			}
			return
		}
	}
}

// save pcapng file ,merge master key into pcapng file TODO
func (pw *PcapWriter) savePcapng() (i int, err error) {

	defer func() {
		//t.tcPacketLocker.Unlock()
	}()
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

// WriteKeyLog writes TLS master secret as a Decryption Secrets Block (DSB)
func (pw *PcapWriter) WriteKeyLog(keylogLine []byte) error {

	// Write as DSB (Decryption Secrets Block) using custom gopacket implementation
	// The cfc4n/gopacket fork includes WriteDecryptionSecretsBlock method
	// Use pcapgo.DSB_SECRETS_TYPE_TLS for TLS key logs
	return pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylogLine)
}

// Flush ensures all buffered data is written to disk
func (pw *PcapWriter) Flush() error {
	// Flush the underlying writer if it supports flushing
	return pw.writer.Flush()
}

// Close closes the PCAPNG writer and flushes any buffered data
// This should be called when the program exits to ensure all data is written
func (pw *PcapWriter) Close() error {
	if pw.isClosed {
		return nil
	}
	defer func() {
		pw.isClosed = true
	}()
	// Stop the Serve goroutine
	pw.ctxCancel()

	// Close the packet channel
	close(pw.packetChan)

	// Flush any remaining data before closing
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
