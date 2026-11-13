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

package pcapng

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	lger "github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output/writers"
)

func TestSessionProcessArgsOptionsKeepPacketBytes(t *testing.T) {
	for _, rawArgs := range [][]byte{[]byte("tool\x00two words\x00\x00参数\x00\xff\x00"), append(bytes.Repeat([]byte{'x'}, 255), 0), bytes.Repeat([]byte{'x'}, 256)} {
		var output bytes.Buffer
		writer, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		s := &Session{encoder: writer, sink: writers.NewIOWriterAdapter(&output, "memory"), queueReady: make(chan struct{}, 1)}
		packet, timestamp := make([]byte, 60), time.Unix(100, 12345)
		args := bytes.Clone(rawArgs)
		truncated := rawArgs[len(rawArgs)-1] != 0
		if err := s.WritePacketWithProcess(packet, timestamp, 42, "tool", 1, args, truncated); err != nil {
			t.Fatal(err)
		}
		args[0] = '!'
		s.tcPackets, _ = s.takePendingData()
		if _, err := s.savePcapng(); err != nil {
			t.Fatal(err)
		}
		reader, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		// The released reader ignores comment options, retaining all existing bytes.
		if !bytes.Equal(data[:60], packet) || !bytes.Equal(data[60:], []byte{0xcc, 0x0c, 0x4c, 0xfc, 0, 0, 0, 42, 4, 't', 'o', 'o', 'l', 1, 1, 0, 0, 0, 0}) || ci.CaptureLength != len(data) || ci.Length != len(data) || !ci.Timestamp.Equal(timestamp) {
			t.Fatal("argv changed packet bytes, lengths or timestamp")
		}
		var encoded strings.Builder
		for blocks := output.Bytes(); len(blocks) > 0; {
			n := int(binary.LittleEndian.Uint32(blocks[4:]))
			if binary.LittleEndian.Uint32(blocks) == 6 {
				options := blocks[28+(len(data)+3)&^3 : n-4]
				for binary.LittleEndian.Uint16(options) != 0 {
					l := int(binary.LittleEndian.Uint16(options[2:]))
					var flag int
					var payload string
					if _, err := fmt.Sscanf(string(options[4:4+l]), "eCapture argv v1 %d %s", &flag, &payload); err != nil || (flag == 1) != truncated {
						t.Fatal("invalid argv comment")
					}
					encoded.WriteString(payload)
					options = options[4+(l+3)&^3:]
				}
			}
			blocks = blocks[n:]
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded.String())
		if err != nil || !bytes.Equal(decoded, rawArgs) {
			t.Fatal("argv truncated or aliased")
		}
	}
}

func TestSessionQueuesBurstWithoutDrop(t *testing.T) {
	t.Parallel()

	pw := &Session{
		queueReady: make(chan struct{}, 1),
	}

	const packetCount = 4096
	for i := 0; i < packetCount; i++ {
		if err := pw.WritePacket([]byte{byte(i)}, time.Unix(0, int64(i))); err != nil {
			t.Fatalf("WritePacket() packet %d error = %v; burst packets must be queued", i, err)
		}
		if err := pw.WriteKeyLog([]byte{byte(i)}); err != nil {
			t.Fatalf("WriteKeyLog() entry %d error = %v; burst keylogs must be queued", i, err)
		}
	}
	if got := len(pw.pendingPackets); got != packetCount {
		t.Fatalf("queued packet count = %d, want %d", got, packetCount)
	}
	if got := len(pw.pendingKeylogs); got != packetCount {
		t.Fatalf("queued keylog count = %d, want %d", got, packetCount)
	}
}

func TestSessionPersistsBurstOnClose(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &Session{
		encoder:    ngWriter,
		sink:       writers.NewIOWriterAdapter(&output, "memory"),
		ctx:        ctx,
		ctxCancel:  cancel,
		queueReady: make(chan struct{}, 1),
		serveDone:  make(chan struct{}),
		logger:     lger.New(io.Discard, false),
	}
	go pw.run()

	const packetCount = 4096
	packet := make([]byte, 60)
	for i := 0; i < packetCount; i++ {
		if err := pw.WritePacket(packet, time.Unix(0, int64(i))); err != nil {
			t.Fatalf("WritePacket() packet %d error = %v", i, err)
		}
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader() error = %v", err)
	}
	var got int
	for {
		if _, _, err = reader.ReadPacketData(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("ReadPacketData() error = %v", err)
		}
		got++
	}
	if got != packetCount {
		t.Fatalf("persisted packet count = %d, want %d", got, packetCount)
	}
}

func TestSessionKeepsDSBBeforeChronologicalPackets(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &Session{
		encoder:    ngWriter,
		sink:       writers.NewIOWriterAdapter(&output, "memory"),
		ctx:        ctx,
		ctxCancel:  cancel,
		tcPackets:  []*TcPacket{},
		queueReady: make(chan struct{}, 1),
		serveDone:  make(chan struct{}),
		logger:     lger.New(io.Discard, false),
	}
	go pw.run()

	baseTime := time.Unix(100, 0)
	for _, timestamp := range []time.Time{baseTime.Add(2 * time.Second), baseTime.Add(time.Second)} {
		if err := pw.WritePacket(make([]byte, 60), timestamp); err != nil {
			t.Fatalf("WritePacket() error = %v", err)
		}
	}
	if err := pw.WriteKeyLog([]byte("CLIENT_TRAFFIC_SECRET_0 random client-secret\n")); err != nil {
		t.Fatalf("WriteKeyLog() error = %v", err)
	}
	if err := pw.WriteKeyLog([]byte("SERVER_TRAFFIC_SECRET_0 random server-secret\n")); err != nil {
		t.Fatalf("WriteKeyLog() error = %v", err)
	}

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

func TestSessionTimedFlushDrainsPendingDSBBeforePackets(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	pw := &Session{
		encoder: ngWriter,
		sink:    writers.NewIOWriterAdapter(&output, "memory"),
		tcPackets: []*TcPacket{{
			ci:   gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), CaptureLength: 60, Length: 60},
			data: make([]byte, 60),
		}},
		pendingKeylogs: [][]byte{[]byte("CLIENT_TRAFFIC_SECRET_0 random client-secret\n")},
		logger:         lger.New(io.Discard, false),
	}

	if _, err := pw.savePacketBatch(); err != nil {
		t.Fatalf("savePacketBatch() error = %v", err)
	}
	assertDSBsBeforePackets(t, output.Bytes(), 1)
}

func TestSessionStartsDSBGracePeriodWithFirstPacket(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &Session{
		encoder:    ngWriter,
		sink:       writers.NewIOWriterAdapter(&output, "memory"),
		ctx:        ctx,
		ctxCancel:  cancel,
		tcPackets:  []*TcPacket{},
		queueReady: make(chan struct{}, 1),
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
	if err := pw.WritePacket(make([]byte, 60), time.Unix(100, 0)); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if err := pw.WriteKeyLog([]byte("CLIENT_TRAFFIC_SECRET_0 random client-secret\n")); err != nil {
		t.Fatalf("WriteKeyLog() error = %v", err)
	}

	// Give an expired-at-start implementation enough time to flush the packet,
	// then enqueue the rest of the handshake secrets within the correct window.
	time.Sleep(3 * flushInterval)
	if err := pw.WriteKeyLog([]byte("SERVER_TRAFFIC_SECRET_0 random server-secret\n")); err != nil {
		t.Fatalf("WriteKeyLog() error = %v", err)
	}

	if err := pw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	assertDSBsBeforePackets(t, output.Bytes(), 2)
}

func TestSessionRestartsDSBGracePeriodForNextBatch(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	ngWriter, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &Session{
		encoder:    ngWriter,
		sink:       writers.NewIOWriterAdapter(&output, "memory"),
		ctx:        ctx,
		ctxCancel:  cancel,
		tcPackets:  []*TcPacket{},
		queueReady: make(chan struct{}, 1),
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
		if err := pw.WritePacket(make([]byte, 60), timestamp); err != nil {
			t.Fatalf("WritePacket() error = %v", err)
		}
	}

	writeTestPacket(time.Unix(100, 0))
	if err := pw.WriteKeyLog([]byte("CLIENT_RANDOM first-random first-secret\n")); err != nil {
		t.Fatalf("WriteKeyLog() error = %v", err)
	}

	// Let the first batch pass its grace deadline and flush before starting a
	// separate handshake in the next batch.
	time.Sleep(gracePeriod + 3*flushInterval)

	writeTestPacket(time.Unix(200, 0))
	// An implementation that keeps the first batch's expired deadline will
	// flush this packet on the next tick, before its secret arrives.
	time.Sleep(5 * flushInterval)
	if err := pw.WriteKeyLog([]byte("CLIENT_RANDOM second-random second-secret\n")); err != nil {
		t.Fatalf("WriteKeyLog() error = %v", err)
	}

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

type failingSessionSink struct {
	fail      atomic.Bool
	writes    atomic.Int64
	root      error
	flushOnly bool
}

func (s *failingSessionSink) Name() string { return "test" }
func (s *failingSessionSink) Write(p []byte) (int, error) {
	s.writes.Add(1)
	if s.fail.Load() && !s.flushOnly {
		return 0, s.root
	}
	return len(p), nil
}
func (s *failingSessionSink) Flush() error {
	if s.fail.Load() && s.flushOnly {
		return s.root
	}
	return nil
}
func (s *failingSessionSink) Close() error { return nil }
func TestSessionStopsOnFirstFailure(t *testing.T) {
	for _, kind := range []string{"packet", "keylog", "flush"} {
		t.Run(kind, func(t *testing.T) {
			root := errors.New("test output failure")
			sink := &failingSessionSink{root: root, flushOnly: kind == "flush"}
			var logs bytes.Buffer
			s, err := NewLowLatencySession(sink, 65535, "lo", "", lger.New(&logs, true))
			if err != nil {
				t.Fatal(err)
			}
			sink.fail.Store(true)
			if kind == "keylog" {
				_ = s.WriteKeyLog([]byte("PRIVATE_KEYLOG\n"))
			} else {
				_ = s.WritePacket(make([]byte, 60), time.Now())
			}
			select {
			case <-s.serveDone:
			case <-time.After(time.Second):
				t.Fatal("background failure did not stop session")
			}
			writes := sink.writes.Load()
			var wg sync.WaitGroup
			for range 32 {
				wg.Go(func() {
					for range 100 {
						if !errors.Is(s.WritePacket(make([]byte, 60), time.Now()), root) || !errors.Is(s.WriteKeyLog([]byte("PRIVATE_KEYLOG\n")), root) {
							t.Error("lost terminal cause")
						}
						_ = s.Flush()
						_ = s.FlushKeylogs()
					}
					_ = s.Close()
				})
			}
			wg.Wait()
			if sink.writes.Load() != writes || !errors.Is(s.serveErr, root) || len(s.pendingPackets) != 0 || len(s.pendingKeylogs) != 0 || len(s.tcPackets) != 0 {
				t.Fatal("failed stream retained or retried output")
			}
			if logs.Len() != 0 {
				t.Fatal("session logged repeated or sensitive failures")
			}
		})
	}
}
