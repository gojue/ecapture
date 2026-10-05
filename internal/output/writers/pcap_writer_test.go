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
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	lger "github.com/gojue/ecapture/v2/internal/logger"
)

func TestPcapWriterKeepsCompleteDSBSetBeforePackets(t *testing.T) {
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

	pw.packetChan <- &TcPacket{
		ci: gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: 60,
			Length:        60,
		},
		data: make([]byte, 60),
	}
	pw.keylogChan <- []byte("CLIENT_TRAFFIC_SECRET_0 random client-secret\n")
	pw.keylogChan <- []byte("SERVER_TRAFFIC_SECRET_0 random server-secret\n")

	if err := pw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	blockTypes, err := parsePcapngBlockTypes(output.Bytes())
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
	if dsbCount != 2 {
		t.Fatalf("DSB count = %d, want 2", dsbCount)
	}
	if firstPacket < 0 {
		t.Fatal("pcapng contains no enhanced packet block")
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
