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
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/websocket"

	internalLogger "github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output/writers"
)

type memorySink struct {
	bytes.Buffer
}

func (s *memorySink) Name() string { return "memory" }
func (s *memorySink) Flush() error { return nil }
func (s *memorySink) Close() error { return nil }

func TestSessionDestinations(t *testing.T) {
	tests := []struct {
		name string
		new  func(*testing.T) (writers.ByteSink, <-chan []byte, func())
	}{
		{
			name: "memory",
			new: func(t *testing.T) (writers.ByteSink, <-chan []byte, func()) {
				sink := &memorySink{}
				result := make(chan []byte, 1)
				return sink, result, func() { result <- append([]byte(nil), sink.Bytes()...) }
			},
		},
		{
			name: "file",
			new: func(t *testing.T) (writers.ByteSink, <-chan []byte, func()) {
				path := filepath.Join(t.TempDir(), "capture.pcapng")
				sink, err := writers.NewWriterFactory().CreateEventSink(writers.EventSinkOptions{
					Format:  writers.EventFormatPcapng,
					Address: path,
				})
				if err != nil {
					t.Fatal(err)
				}
				result := make(chan []byte, 1)
				return sink, result, func() {
					data, readErr := os.ReadFile(path)
					if readErr != nil {
						t.Error(readErr)
					}
					result <- data
				}
			},
		},
		{
			name: "TCP",
			new: func(t *testing.T) (writers.ByteSink, <-chan []byte, func()) {
				address, result, stop := startTCPReceiver(t)
				sink, err := writers.NewWriterFactory().CreateEventSink(writers.EventSinkOptions{
					Format:  writers.EventFormatPcapng,
					Address: "tcp://" + address,
				})
				if err != nil {
					t.Fatal(err)
				}
				return sink, result, stop
			},
		},
		{
			name: "WebSocket",
			new: func(t *testing.T) (writers.ByteSink, <-chan []byte, func()) {
				url, result, stop := startWebSocketReceiver(t)
				sink, err := writers.NewWriterFactory().CreateEventSink(writers.EventSinkOptions{
					Format:  writers.EventFormatPcapng,
					Address: url,
				})
				if err != nil {
					t.Fatal(err)
				}
				return sink, result, stop
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink, result, stop := test.new(t)
			session, err := NewSession(sink, 65535, "lo", "", internalLogger.New(io.Discard, false))
			if err != nil {
				t.Fatal(err)
			}
			if err = session.WriteKeyLog([]byte("CLIENT_RANDOM aa bb\n")); err != nil {
				t.Fatal(err)
			}
			if err = session.WritePacket(make([]byte, 60), time.Unix(100, 0)); err != nil {
				t.Fatal(err)
			}
			if err = session.Flush(); err != nil {
				t.Fatal(err)
			}
			if err = session.Close(); err != nil {
				t.Fatal(err)
			}
			if err = sink.Close(); err != nil {
				t.Fatal(err)
			}
			stop()
			assertPcapngPacketAndDSB(t, <-result)
		})
	}
}

func startTCPReceiver(t *testing.T) (string, <-chan []byte, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- nil
			return
		}
		data, _ := io.ReadAll(conn)
		_ = conn.Close()
		result <- data
	}()
	var once sync.Once
	return listener.Addr().String(), result, func() { once.Do(func() { _ = listener.Close() }) }
}

func startWebSocketReceiver(t *testing.T) (string, <-chan []byte, func()) {
	t.Helper()
	result := make(chan []byte, 1)
	server := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		var stream bytes.Buffer
		for {
			var frame []byte
			if err := websocket.Message.Receive(conn, &frame); err != nil {
				break
			}
			_, _ = stream.Write(frame)
		}
		result <- stream.Bytes()
	}))
	var once sync.Once
	return "ws" + server.URL[4:] + "/", result, func() { once.Do(server.Close) }
}

func assertPcapngPacketAndDSB(t *testing.T, data []byte) {
	t.Helper()
	if len(data) == 0 {
		t.Fatal("empty pcapng stream")
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("invalid pcapng stream: %v", err)
	}
	if _, _, err = reader.ReadPacketData(); err != nil {
		t.Fatalf("pcapng packet read failed: %v", err)
	}
	blockTypes, err := parsePcapngBlockTypes(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, blockType := range blockTypes {
		if blockType == 0x0000000a {
			return
		}
	}
	t.Fatal("pcapng stream has no Decryption Secrets Block")
}
