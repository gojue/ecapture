// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	lger "github.com/gojue/ecapture/v2/internal/logger"
)

func TestPcapWriterKeepsDSBBeforeChronologicalPackets(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &PcapWriter{
		writer:     ngWriter,
		ctx:        ctx,
		ctxCancel:  cancel,
		tcPackets:  []*TcPacket{},
		packetChan: make(chan *TcPacket),
		keylogChan: make(chan []byte),
		serveDone:  make(chan struct{}),
		logger:     lger.New(io.Discard, false),
	}
	go pw.Serve()

	baseTime := time.Unix(100, 0)
	for _, timestamp := range []time.Time{baseTime.Add(2 * time.Second), baseTime.Add(time.Second)} {
		pw.packetChan <- &TcPacket{
			ci: gopacket.CaptureInfo{
				Timestamp:     timestamp,
				CaptureLength: 60,
				Length:        60,
			},
			data: make([]byte, 60),
		}
	}
	pw.keylogChan <- []byte("CLIENT_TRAFFIC_SECRET_0 random client-secret\n")
	pw.keylogChan <- []byte("SERVER_TRAFFIC_SECRET_0 random server-secret\n")

	if err := pw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	assertDSBsBeforePackets(t, output.Bytes(), 2)

	reader, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader() error = %v", err)
	}
	var packetTimes []time.Time
	for {
		_, captureInfo, readErr := reader.ReadPacketData()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			t.Fatalf("ReadPacketData() error = %v", readErr)
		}
		packetTimes = append(packetTimes, captureInfo.Timestamp)
	}
	if len(packetTimes) != 2 {
		t.Fatalf("packet count = %d, want 2", len(packetTimes))
	}
	if packetTimes[0].After(packetTimes[1]) {
		t.Fatalf("packet timestamps are out of order: %v then %v", packetTimes[0], packetTimes[1])
	}
}

func TestPcapWriterStartsDSBGracePeriodWithFirstPacket(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &PcapWriter{
		writer:     ngWriter,
		ctx:        ctx,
		ctxCancel:  cancel,
		tcPackets:  []*TcPacket{},
		packetChan: make(chan *TcPacket),
		keylogChan: make(chan []byte),
		serveDone:  make(chan struct{}),
		logger:     lger.New(io.Discard, false),
	}

	const (
		flushInterval = 10 * time.Millisecond
		gracePeriod   = 80 * time.Millisecond
	)
	go pw.serve(flushInterval, gracePeriod)

	// Leave the capture idle beyond the grace period. The grace deadline must
	// still start when the first packet arrives, not when Serve starts.
	time.Sleep(2 * gracePeriod)
	pw.packetChan <- &TcPacket{
		ci: gopacket.CaptureInfo{
			Timestamp:     time.Unix(100, 0),
			CaptureLength: 60,
			Length:        60,
		},
		data: make([]byte, 60),
	}
	pw.keylogChan <- []byte("CLIENT_TRAFFIC_SECRET_0 random client-secret\n")

	// Give an expired-at-start implementation enough time to flush the packet,
	// then enqueue the rest of the handshake secrets within the correct window.
	time.Sleep(3 * flushInterval)
	pw.keylogChan <- []byte("SERVER_TRAFFIC_SECRET_0 random server-secret\n")

	if err := pw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	assertDSBsBeforePackets(t, output.Bytes(), 2)
}

func TestPcapWriterRestartsDSBGracePeriodForNextBatch(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &PcapWriter{
		writer:     ngWriter,
		ctx:        ctx,
		ctxCancel:  cancel,
		tcPackets:  []*TcPacket{},
		packetChan: make(chan *TcPacket),
		keylogChan: make(chan []byte),
		serveDone:  make(chan struct{}),
		logger:     lger.New(io.Discard, false),
	}

	const (
		flushInterval = 20 * time.Millisecond
		gracePeriod   = 200 * time.Millisecond
	)
	go pw.serve(flushInterval, gracePeriod)

	writeTestPacket := func(timestamp time.Time) {
		t.Helper()
		pw.packetChan <- &TcPacket{
			ci: gopacket.CaptureInfo{
				Timestamp:     timestamp,
				CaptureLength: 60,
				Length:        60,
			},
			data: make([]byte, 60),
		}
	}

	writeTestPacket(time.Unix(100, 0))
	pw.keylogChan <- []byte("CLIENT_RANDOM first-random first-secret\n")

	// Let the first batch pass its grace deadline and flush before starting a
	// separate handshake in the next batch.
	time.Sleep(gracePeriod + 3*flushInterval)

	writeTestPacket(time.Unix(200, 0))
	// An implementation that keeps the first batch's expired deadline will
	// flush this packet on the next tick, before its secret arrives.
	time.Sleep(5 * flushInterval)
	pw.keylogChan <- []byte("CLIENT_RANDOM second-random second-secret\n")

	if err := pw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	assertDSBPrecedesEachPacketBatch(t, output.Bytes(), 2)
}

func assertDSBsBeforePackets(t *testing.T, data []byte, wantDSBs int) {
	t.Helper()

	blockTypes, err := parsePcapngBlockTypes(data)
	if err != nil {
		t.Fatalf("parsePcapngBlockTypes() error = %v", err)
	}
	const (
		dsbBlock = uint32(0x0000000a)
		epbBlock = uint32(0x00000006)
	)
	firstPacket := -1
	dsbCount := 0
	for index, blockType := range blockTypes {
		switch blockType {
		case dsbBlock:
			dsbCount++
			if firstPacket >= 0 {
				t.Fatalf("DSB at block %d appears after packet block %d", index, firstPacket)
			}
		case epbBlock:
			if firstPacket < 0 {
				firstPacket = index
			}
		}
	}
	if dsbCount != wantDSBs {
		t.Fatalf("DSB count = %d, want %d", dsbCount, wantDSBs)
	}
	if firstPacket < 0 {
		t.Fatal("pcapng contains no enhanced packet block")
	}
}

func assertDSBPrecedesEachPacketBatch(t *testing.T, data []byte, wantBatches int) {
	t.Helper()

	blockTypes, err := parsePcapngBlockTypes(data)
	if err != nil {
		t.Fatalf("parsePcapngBlockTypes() error = %v", err)
	}
	const (
		dsbBlock = uint32(0x0000000a)
		epbBlock = uint32(0x00000006)
	)
	var dsbIndexes []int
	var packetIndexes []int
	for index, blockType := range blockTypes {
		switch blockType {
		case dsbBlock:
			dsbIndexes = append(dsbIndexes, index)
		case epbBlock:
			packetIndexes = append(packetIndexes, index)
		}
	}
	if len(dsbIndexes) != wantBatches {
		t.Fatalf("DSB count = %d, want %d", len(dsbIndexes), wantBatches)
	}
	if len(packetIndexes) != wantBatches {
		t.Fatalf("packet count = %d, want %d", len(packetIndexes), wantBatches)
	}
	for batch := 0; batch < wantBatches; batch++ {
		if dsbIndexes[batch] > packetIndexes[batch] {
			t.Fatalf("batch %d DSB at block %d appears after packet block %d", batch+1, dsbIndexes[batch], packetIndexes[batch])
		}
		if batch > 0 && dsbIndexes[batch] < packetIndexes[batch-1] {
			t.Fatalf("batch %d DSB at block %d appears before prior packet block %d", batch+1, dsbIndexes[batch], packetIndexes[batch-1])
		}
	}
}

func parsePcapngBlockTypes(data []byte) ([]uint32, error) {
	var blockTypes []uint32
	for len(data) > 0 {
		if len(data) < 12 {
			return nil, fmt.Errorf("truncated block header: %d bytes", len(data))
		}
		blockLength := binary.LittleEndian.Uint32(data[4:8])
		if blockLength < 12 || blockLength%4 != 0 || uint64(blockLength) > uint64(len(data)) {
			return nil, fmt.Errorf("invalid block length %d", blockLength)
		}
		blockTypes = append(blockTypes, binary.LittleEndian.Uint32(data[:4]))
		data = data[blockLength:]
	}
	return blockTypes, nil
}
