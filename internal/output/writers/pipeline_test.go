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
	"errors"
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
)

type recordingSink struct {
	mu         sync.Mutex
	data       bytes.Buffer
	flushErr   error
	closeErr   error
	flushCalls int
	closeCalls int
	closed     bool
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func (s *recordingSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errors.New("closed")
	}
	return s.data.Write(p)
}

func (s *recordingSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushCalls++
	return s.flushErr
}

func (s *recordingSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalls++
	s.closed = true
	return s.closeErr
}

func (s *recordingSink) Name() string { return "recording" }

func (s *recordingSink) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data.Bytes()...)
}

func TestKeylogWriterOwnsGenericSink(t *testing.T) {
	flushErr := errors.New("flush failed")
	closeErr := errors.New("close failed")
	sink := &recordingSink{flushErr: flushErr, closeErr: closeErr}
	writer := NewKeylogWriter(sink)
	input := []byte("CLIENT_RANDOM aa bb\r\n")
	original := append([]byte(nil), input...)
	if n, err := writer.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(input))
	}
	if !bytes.Equal(input, original) {
		t.Fatal("Write mutated caller data")
	}
	if got := string(sink.Bytes()); got != "CLIENT_RANDOM aa bb\n" {
		t.Fatalf("encoded keylog = %q", got)
	}
	first := writer.Close()
	second := writer.Close()
	if !errors.Is(first, flushErr) || !errors.Is(first, closeErr) {
		t.Fatalf("Close() did not aggregate errors: %v", first)
	}
	if first.Error() != second.Error() {
		t.Fatalf("repeated Close() changed error: first=%v second=%v", first, second)
	}
	if sink.closeCalls != 1 {
		t.Fatalf("sink Close() calls = %d, want 1", sink.closeCalls)
	}
}

func TestIOWriterAdapterReportsShortWriteAndConcurrentClose(t *testing.T) {
	adapter := NewIOWriterAdapter(shortWriter{}, "short")
	if _, err := adapter.Write([]byte("abc")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() error = %v, want io.ErrShortWrite", err)
	}

	sink := &recordingSink{}
	closable := NewIOWriterAdapter(sink, "recording")
	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = closable.Close()
		}()
	}
	wg.Wait()
	if sink.closeCalls != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", sink.closeCalls)
	}
	if _, err := closable.Write([]byte("closed")); err == nil {
		t.Fatal("write after concurrent Close should fail")
	}
}

func TestWriterFactoryValidationMatrix(t *testing.T) {
	factory := NewWriterFactory()
	tests := []struct {
		name    string
		options EventSinkOptions
		wantErr bool
	}{
		{name: "text default stdout", options: EventSinkOptions{Format: EventFormatText}},
		{name: "explicit keylog stdout", options: EventSinkOptions{Format: EventFormatKeylog, Address: "stdout"}},
		{name: "pcap TCP", options: EventSinkOptions{Format: EventFormatPcapng, Address: "tcp://127.0.0.1:9000"}},
		{name: "binary websocket", options: EventSinkOptions{Format: EventFormatPcapng, Address: "ws://127.0.0.1:9000/stream"}},
		{name: "file URI", options: EventSinkOptions{Format: EventFormatKeylog, Address: "file:///tmp/a.keys"}},
		{name: "keylog needs destination", options: EventSinkOptions{Format: EventFormatKeylog}, wantErr: true},
		{name: "pcap needs destination", options: EventSinkOptions{Format: EventFormatPcapng}, wantErr: true},
		{name: "unsupported scheme", options: EventSinkOptions{Format: EventFormatText, Address: "udp://127.0.0.1:9"}, wantErr: true},
		{name: "malformed TCP", options: EventSinkOptions{Format: EventFormatText, Address: "tcp://missing-port"}, wantErr: true},
		{name: "pcap rotation", options: EventSinkOptions{Format: EventFormatPcapng, Address: "/tmp/a.pcapng", RotateConfig: &RotateConfig{EnableRotate: true}}, wantErr: true},
		{name: "network rotation", options: EventSinkOptions{Format: EventFormatText, Address: "tcp://127.0.0.1:9000", RotateConfig: &RotateConfig{EnableRotate: true}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := factory.ValidateEventSinkAddress(test.options)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateEventSinkAddress() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
	if err := ValidateChannelSeparation(EventFormatPcapng, "stdout", "stdout"); err == nil {
		t.Fatal("pcapng and operational logs must not share stdout")
	}
}

func TestNormalizeEventAddressIsIdempotent(t *testing.T) {
	address, err := NormalizeEventAddress(EventFormatKeylog, "", "/tmp/a.keys", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeEventAddress(EventFormatKeylog, address, "/tmp/a.keys", "")
	if err != nil || second != address {
		t.Fatalf("second normalization = (%q, %v), want (%q, nil)", second, err, address)
	}
	if _, err := NormalizeEventAddress(EventFormatKeylog, "tcp://127.0.0.1:1", "/tmp/a.keys", ""); err == nil {
		t.Fatal("explicit and legacy primary destinations must conflict")
	}
}

func TestTextAndOperationalSinkDestinations(t *testing.T) {
	const payload = "output-pipeline-record\n"
	tests := []struct {
		name string
		new  func(*testing.T, bool) (ByteSink, <-chan []byte, func())
	}{
		{
			name: "file",
			new: func(t *testing.T, operational bool) (ByteSink, <-chan []byte, func()) {
				path := filepath.Join(t.TempDir(), "output.log")
				var (
					sink ByteSink
					err  error
				)
				if operational {
					sink, err = NewWriterFactory().CreateOperationalSink(path, nil)
				} else {
					sink, err = NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatText, Address: path})
				}
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
			new: func(t *testing.T, operational bool) (ByteSink, <-chan []byte, func()) {
				address, result, stop := startTCPReceiver(t)
				var (
					sink ByteSink
					err  error
				)
				if operational {
					sink, err = NewWriterFactory().CreateOperationalSink("tcp://"+address, nil)
				} else {
					sink, err = NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatText, Address: "tcp://" + address})
				}
				if err != nil {
					t.Fatal(err)
				}
				return sink, result, stop
			},
		},
		{
			name: "WebSocket",
			new: func(t *testing.T, operational bool) (ByteSink, <-chan []byte, func()) {
				url, result, stop := startWebSocketReceiver(t)
				var (
					sink ByteSink
					err  error
				)
				if operational {
					sink, err = NewWriterFactory().CreateOperationalSink(url, nil)
				} else {
					sink, err = NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatText, Address: url})
				}
				if err != nil {
					t.Fatal(err)
				}
				return sink, result, stop
			},
		},
	}
	for _, operational := range []bool{false, true} {
		channel := "event"
		if operational {
			channel = "operational"
		}
		for _, test := range tests {
			t.Run(channel+"/"+test.name, func(t *testing.T) {
				sink, result, stop := test.new(t, operational)
				if _, err := sink.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
				if err := sink.Flush(); err != nil {
					t.Fatal(err)
				}
				if err := sink.Close(); err != nil {
					t.Fatal(err)
				}
				stop()
				if got := string(<-result); got != payload {
					t.Fatalf("received data = %q, want %q", got, payload)
				}
			})
		}
	}
}

func TestKeylogWriterDestinations(t *testing.T) {
	const record = "CLIENT_RANDOM aa bb"
	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keys.log")
		sink, err := NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatKeylog, Address: path})
		if err != nil {
			t.Fatal(err)
		}
		writer := NewKeylogWriter(sink)
		if _, err = writer.Write([]byte(record)); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != record+"\n" {
			t.Fatalf("file data = %q", data)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("keylog permissions = %o, want 600", got)
		}
	})

	t.Run("TCP", func(t *testing.T) {
		address, received, stop := startTCPReceiver(t)
		sink, err := NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatKeylog, Address: "tcp://" + address})
		if err != nil {
			t.Fatal(err)
		}
		writer := NewKeylogWriter(sink)
		if _, err = writer.Write([]byte(record)); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		stop()
		if got := string(<-received); got != record+"\n" {
			t.Fatalf("TCP data = %q", got)
		}
	})

	t.Run("WebSocket", func(t *testing.T) {
		url, received, stop := startWebSocketReceiver(t)
		sink, err := NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatKeylog, Address: url})
		if err != nil {
			t.Fatal(err)
		}
		writer := NewKeylogWriter(sink)
		if _, err = writer.Write([]byte(record)); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		stop()
		if got := string(<-received); got != record+"\n" {
			t.Fatalf("WebSocket data = %q", got)
		}
	})
}

func TestPcapngGenericStreamDestinations(t *testing.T) {
	tests := []struct {
		name string
		new  func(*testing.T) (ByteSink, <-chan []byte, func())
	}{
		{
			name: "memory",
			new: func(t *testing.T) (ByteSink, <-chan []byte, func()) {
				sink := &recordingSink{}
				result := make(chan []byte, 1)
				return sink, result, func() { result <- sink.Bytes() }
			},
		},
		{
			name: "file",
			new: func(t *testing.T) (ByteSink, <-chan []byte, func()) {
				path := filepath.Join(t.TempDir(), "capture.pcapng")
				sink, err := NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatPcapng, Address: path})
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
			new: func(t *testing.T) (ByteSink, <-chan []byte, func()) {
				address, result, stop := startTCPReceiver(t)
				sink, err := NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatPcapng, Address: "tcp://" + address})
				if err != nil {
					t.Fatal(err)
				}
				return sink, result, stop
			},
		},
		{
			name: "WebSocket",
			new: func(t *testing.T) (ByteSink, <-chan []byte, func()) {
				url, result, stop := startWebSocketReceiver(t)
				sink, err := NewWriterFactory().CreateEventSink(EventSinkOptions{Format: EventFormatPcapng, Address: url})
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
			pcap, err := NewPcapWriter(sink, 65535, "lo", "", internalLogger.New(io.Discard, false))
			if err != nil {
				t.Fatal(err)
			}
			if err = pcap.WriteKeyLog([]byte("CLIENT_RANDOM aa bb\n")); err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 60)
			if err = pcap.WritePacket(packet, time.Unix(100, 0)); err != nil {
				t.Fatal(err)
			}
			if err = pcap.Flush(); err != nil {
				t.Fatal(err)
			}
			if err = pcap.Close(); err != nil {
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
	var hasDSB bool
	for _, blockType := range blockTypes {
		if blockType == 0x0000000a {
			hasDSB = true
			break
		}
	}
	if !hasDSB {
		t.Fatal("pcapng stream has no Decryption Secrets Block")
	}
}
