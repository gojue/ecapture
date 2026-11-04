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

package decrypt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

func TestFormatMessageRaw(t *testing.T) {
	for _, test := range []struct {
		name, protocol, direction string
		data                      []byte
		metadata                  map[string]any
		wantFields                []string
	}{
		{
			name: "tls_binary_request", protocol: "tls", direction: "request",
			data:     []byte{0, 0xff, '\r', '\n', 0x80, 'A'},
			metadata: map[string]any{"kind": "stream_chunk", "offset": uint64(0), "end": false},
			wantFields: []string{"tls client_to_server 192.0.2.1:43210 -> 192.0.2.2:443",
				"kind=stream_chunk offset=0 end=false length=6 encoding=hex"},
		},
		{
			name: "quic_response_final_chunk", protocol: "quic", direction: "response",
			data: []byte{0xfe, 0, '\n'},
			metadata: map[string]any{"kind": "stream_chunk", "offset": uint64(4294967297),
				"end": true, "stream_id": uint64(4294967300)},
			wantFields: []string{"quic server_to_client 192.0.2.2:443 -> 192.0.2.1:43210",
				"kind=stream_chunk offset=4294967297 end=true length=3 encoding=hex stream=4294967300"},
		},
		{
			name: "empty_end", protocol: "tls", direction: "response",
			metadata:   map[string]any{"kind": "stream_end", "offset": uint64(6), "end": true},
			wantFields: []string{"tls server_to_client", "kind=stream_end offset=6 end=true length=0 encoding=hex"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := formatTestPacket(test.protocol, test.direction, test.data)
			packet.Metadata = test.metadata
			lines := strings.Split(string(formatMessage(packet)), "\n")
			if len(lines) != 4 || lines[2] != "" || lines[3] != "" {
				t.Fatalf("raw output framing = %q", lines)
			}
			if !strings.HasPrefix(lines[0], "[2026-11-04T12:00:00.123456789Z] ") ||
				!strings.Contains(lines[0], "connection=\""+packet.ConnectionID()+"\"") {
				t.Fatalf("missing timestamp or connection: %s", lines[0])
			}
			for _, field := range test.wantFields {
				if !strings.Contains(lines[0], field) {
					t.Errorf("header %q does not contain %q", lines[0], field)
				}
			}
			decoded, err := hex.DecodeString(lines[1])
			if err != nil || !bytes.Equal(decoded, test.data) {
				t.Fatalf("raw payload did not round-trip: got %x, err %v", decoded, err)
			}
			if _, ok := test.metadata["stream_id"]; !ok && strings.Contains(lines[0], " stream=") {
				t.Fatalf("TLS output unexpectedly has stream ID: %s", lines[0])
			}
		})
	}
}

func TestFormatMessageHTTP(t *testing.T) {
	for _, test := range []struct {
		name, direction, data string
		metadata              map[string]any
		want                  string
	}{
		{
			name: "host", direction: "request", data: "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
			metadata: map[string]any{"host": "example.test", "authority": "ignored.test"},
			want:     "request 192.0.2.1:43210 -> 192.0.2.2:443 host=\"example.test\" domain_source=\"Host\"",
		},
		{
			name: "authority", direction: "request", data: "body",
			metadata: map[string]any{"authority": "example.test", "stream_id": uint32(3)},
			want:     "request 192.0.2.1:43210 -> 192.0.2.2:443 host=\"example.test\" domain_source=\":authority\"",
		},
		{
			name: "response_server_fallback", direction: "response",
			want: "response 192.0.2.2:443 -> 192.0.2.1:43210 host=\"192.0.2.2\" domain_source=\"server_ip\"",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := formatTestPacket("http/1.1", test.direction, []byte(test.data))
			packet.Metadata = test.metadata
			want := "[2026-11-04T12:00:00.123456789Z] http/1.1 " + test.want +
				" connection=\"17-4-client/192.0.2.1:43210--192.0.2.2:443/tcp#2\""
			if test.name == "authority" {
				want += " stream=3"
			}
			want += "\n" + test.data
			if !strings.HasSuffix(test.data, "\n") {
				want += "\n"
			}
			want += "\n"
			if got := string(formatMessage(packet)); got != want {
				t.Fatalf("HTTP output = %q, want %q", got, want)
			}
		})
	}
}

func TestSinkInvalidPcapngUnblocksWriteAndClose(t *testing.T) {
	for _, raw := range []bool{false, true} {
		name := "parsed"
		if raw {
			name = "raw"
		}
		t.Run(name, func(t *testing.T) {
			sink, err := NewSink(filepath.Join(t.TempDir(), "events.log"), "", nil, nil, types.DecryptOptions{RawChunks: raw})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				// Unblock a pending write even when the regression under test occurs.
				_ = sink.pipeWriter.Close()
				_ = sink.Close()
			})
			writeDone := make(chan error, 1)
			go func() {
				// More than the initial header ensures rejection leaves a pending write.
				_, err := sink.Write(bytes.Repeat([]byte{0xff}, 64))
				writeDone <- err
			}()
			select {
			case err := <-writeDone:
				if err == nil {
					t.Fatal("invalid pcapng write succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("invalid pcapng left Write blocked")
			}
			closeDone := make(chan error, 1)
			go func() { closeDone <- sink.Close() }()
			select {
			case err := <-closeDone:
				if err == nil {
					t.Fatal("Close lost the pcapng parse error")
				}
				if again := sink.Close(); !errors.Is(again, err) {
					t.Fatalf("repeated Close changed error: %v, then %v", err, again)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("invalid pcapng left Close blocked")
			}
			if _, err := sink.Write([]byte("closed")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("Write after Close = %v, want io.ErrClosedPipe", err)
			}
		})
	}
}

func formatTestPacket(protocol, direction string, data []byte) *types.DecryptedPacket {
	transport := "tcp"
	if protocol == "quic" {
		transport = "udp"
	}
	return types.NewDecryptedPacket(transport, protocol, direction, data,
		time.Date(2026, time.November, 4, 12, 0, 0, 123456789, time.UTC), types.ConnectionKey{
			SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 43210, DstPort: 443,
			Proto: transport, Pid: 17, FD: 4, ProcessName: "client", Generation: 2,
		})
}
