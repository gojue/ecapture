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
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	decryptor "github.com/gojue/ecapture_decryptor"
	sdkcrypto "github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"

	"github.com/gojue/ecapture/v2/internal/domain"
	captureerrors "github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/logger"
)

func TestMessageEnvelopePreservesProcessAndRepresentation(t *testing.T) {
	for _, structured := range []bool{false, true} {
		packet := formatTestPacket("http/3", "response", []byte{0, 0xff, 'A'})
		packet.ProcessArgs = &types.ProcessArgs{Data: append([]byte("demo\x00--label\x00"), bytes.Repeat([]byte("x"), 243)...), Truncated: true}
		packet.Metadata["stream_id"] = uint64(0)
		packet.Metadata["tls"] = map[string]string{"version": "TLS 1.3", "ja3": "client-fingerprint"}
		if structured {
			packet.Metadata["kind"] = "datagram"
		}
		formatted, err := formatMessage(packet)
		if err != nil {
			t.Fatal(err)
		}
		envelope := messageEnvelope(packet, formatted, 7)
		if envelope.PID != 17 || envelope.ProcessName != "client" || envelope.StreamID != "0" {
			t.Fatalf("lost process or zero stream metadata: PID=%d name=%q stream=%q", envelope.PID, envelope.ProcessName, envelope.StreamID)
		}
		if !bytes.Equal(envelope.ProcessArgs, packet.ProcessArgs.Data) || !envelope.ProcessArgsTruncated {
			t.Fatal("lost captured argv or truncation metadata")
		}
		packet.ProcessArgs.Data[0] = '!'
		if envelope.ProcessArgs[0] != 'd' {
			t.Fatal("captured argv aliases SDK memory")
		}
		if envelope.UUID != packet.ConnectionID() || envelope.Direction != "response" || envelope.Sequence != 7 ||
			envelope.Format != domain.CaptureFormatText || envelope.Sensitivity != domain.SensitivitySensitive {
			t.Fatal("captured metadata changed")
		}
		want := packet.Data
		if structured {
			want = formatted
		}
		if !bytes.Equal(envelope.Payload, want) || envelope.OriginalLength != uint32(len(want)) {
			t.Fatal("captured representation changed")
		}
		if envelope.TLS["version"] != "TLS 1.3" {
			t.Fatal("TLS metadata lost")
		}
		packet.Metadata["tls"].(map[string]string)["version"] = "changed"
		if envelope.TLS["version"] != "TLS 1.3" {
			t.Fatal("TLS metadata aliases SDK state")
		}
		original := append([]byte(nil), envelope.Payload...)
		packet.Data[0] = 1
		formatted[0] = '!'
		if !bytes.Equal(envelope.Payload, original) {
			t.Fatal("published payload aliases SDK memory")
		}
	}
	packet := formatTestPacket("http/1.1", "request", nil)
	packet.PID = -1
	packet.PName = ""
	if envelope := messageEnvelope(packet, nil, 1); envelope.PID != 0 || envelope.ProcessName != "" {
		t.Fatal("unknown process must remain unknown")
	}
}

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
			output, err := formatMessage(packet)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(output), "\n")
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
			output, err := formatMessage(packet)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(output); got != want {
				t.Fatalf("HTTP output = %q, want %q", got, want)
			}
		})
	}
}

func TestFormatMessageStructuredMetadata(t *testing.T) {
	for _, test := range []struct {
		name     string
		metadata map[string]any
	}{
		{"headers", map[string]any{"kind": "headers", "headers": map[string][]string{"content-type": {"text/event-stream"}}, "request_id": uint64(1)}},
		{"trailers", map[string]any{"kind": "trailers", "trailers": map[string][]string{"grpc-status": {"0"}}}},
		{"empty_datagram", map[string]any{"kind": "datagram", "encryption_level": "0rtt", "early_data": "rejected"}},
		{"dtls_record", map[string]any{"kind": "datagram", "epoch": uint16(1), "sequence": uint64(281474976710655)}},
		{"inner_tls", map[string]any{"tls_depth": 1, "parent_tls_depth": 0, "upgrade_protocol": "https-connect"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := formatTestPacket("quic", "response", nil)
			packet.Metadata = test.metadata
			output, err := formatMessage(packet)
			if err != nil {
				t.Fatal(err)
			}
			header, payload, _ := strings.Cut(string(output), "\n")
			if payload != "\n\n" || !strings.Contains(header, "length=0 encoding=hex") {
				t.Fatalf("empty event was lost: %q", output)
			}
			if strings.Contains(header, " offset=") || strings.Contains(header, " end=") || strings.Contains(header, " stream=") {
				t.Fatalf("invented stream metadata: %s", header)
			}
			_, metadata, ok := strings.Cut(header, " metadata=")
			if !ok || !json.Valid([]byte(metadata)) {
				t.Fatalf("missing JSON metadata: %s", header)
			}
			want, err := json.Marshal(test.metadata)
			if err != nil || metadata != string(want) {
				t.Fatalf("metadata changed: got %s, want %s, err %v", metadata, want, err)
			}
		})
	}
}

func TestSinkInvalidOptionsLeaveFilesUntouched(t *testing.T) {
	events, pcap := filepath.Join(t.TempDir(), "events.log"), filepath.Join(t.TempDir(), "capture.pcapng")
	for _, path := range []string{events, pcap} {
		if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if sink, err := NewSink(events, pcap, nil, nil, types.DecryptOptions{RawChunks: true, HTTPEvents: true}); err == nil || sink != nil {
		t.Fatalf("invalid options accepted: %v, %v", sink, err)
	}
	for _, path := range []string{events, pcap} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "existing" {
			t.Fatalf("invalid options modified destination: %q, %v", data, err)
		}
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

func TestSinkBackgroundTermination(t *testing.T) {
	root := &os.PathError{Op: "read", Path: "SENSITIVE", Err: io.ErrUnexpectedEOF}
	for _, result := range []error{root, nil, io.EOF, context.Canceled, errors.Join(context.Canceled, root), errors.Join(root, sdkcrypto.ErrKeyLogResourceLimit)} {
		t.Run(fmt.Sprintf("%T", result), func(t *testing.T) {
			release := make(chan struct{})
			failures := make(chan error, 10)
			s, err := newSink(context.Background(), func(err error) { failures <- err }, filepath.Join(t.TempDir(), "plain"), "", nil, nil, types.DecryptOptions{},
				func(context.Context, io.ReadCloser, func(*types.DecryptedPacket) error, types.DecryptOptions) error {
					<-release
					return result
				})
			if err != nil {
				t.Fatal(err)
			}
			close(release)
			var terminal error
			select {
			case terminal = <-failures:
			case <-time.After(time.Second):
				t.Fatal("idle failure was not reported")
			}
			if !captureerrors.IsPipelineError(terminal) {
				t.Fatal("missing terminal classification")
			}
			if result != nil && !errors.Is(terminal, result) {
				t.Fatal("lost cause")
			}
			if errors.Is(result, root) {
				var pathErr *os.PathError
				if !errors.As(terminal, &pathErr) {
					t.Fatal("lost errors.As")
				}
			}
			if errors.Is(result, sdkcrypto.ErrKeyLogResourceLimit) && !strings.Contains(terminal.Error(), "keylog import resource limit exceeded") {
				t.Fatal("history masked resource limit reason")
			}
			if strings.Contains(terminal.Error(), "SENSITIVE") {
				t.Fatal("sensitive cause rendered")
			}
			var wg sync.WaitGroup
			for range 64 {
				wg.Go(func() {
					for range 100 {
						_, _ = s.Write([]byte("secret"))
						_ = s.Flush()
					}
					_ = s.Close()
				})
			}
			wg.Wait()
			if len(failures) != 0 {
				t.Fatal("reported failure more than once")
			}
			if !errors.Is(s.Close(), terminal) {
				t.Fatal("close lost terminal error")
			}
		})
	}
}

func TestSinkCloseUnblocksConcurrentWrite(t *testing.T) {
	entered := make(chan struct{})
	s, err := newSink(context.Background(), nil, filepath.Join(t.TempDir(), "plain"), "", nil, nil, types.DecryptOptions{},
		func(ctx context.Context, input io.ReadCloser, _ func(*types.DecryptedPacket) error, _ types.DecryptOptions) error {
			close(entered)
			// Delay consumption until Close has a chance to interrupt the writer.
			<-ctx.Done()
			return ctx.Err()
		})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	writing := make(chan struct{})
	go func() { _, _ = s.Write(make([]byte, 1<<16)); close(writing) }()
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case <-done:
	case <-time.After(2 * shutdownTimeout):
		t.Fatal("close deadlocked behind writer")
	}
	select {
	case <-writing:
	case <-time.After(time.Second):
		t.Fatal("write remained blocked")
	}
}

func TestSinkNormalEOFAndCancel(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		s, err := newSink(ctx, func(error) { t.Error("normal shutdown reported failure") }, filepath.Join(t.TempDir(), "plain"), "", nil, nil, types.DecryptOptions{},
			func(_ context.Context, input io.ReadCloser, _ func(*types.DecryptedPacket) error, _ types.DecryptOptions) error {
				_, err := io.Copy(io.Discard, input)
				return err
			})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Write([]byte("input")); err != nil {
			t.Fatal(err)
		}
		if cancelFirst {
			cancel()
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		cancel()
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		s.Fail(context.DeadlineExceeded)
		if s.Err() != nil {
			t.Fatal("late deadline changed completed shutdown")
		}
	}
}

func TestDiagnosticLogBoundedAndPrivate(t *testing.T) {
	var logs bytes.Buffer
	observer := diagnosticLogger(logger.New(&logs, true))
	for range 10000 {
		observer(types.Diagnostic{Code: "authentication_failed", ConnectionID: "PRIVATE_CONNECTION"})
	}
	if bytes.Count(logs.Bytes(), []byte("decrypt diagnostic")) != 1 || strings.Contains(logs.String(), "PRIVATE_CONNECTION") {
		t.Fatal("diagnostics unbounded or sensitive")
	}
}

// recordingTLSConn records real crypto/tls ciphertext, not decrypted fixtures.
type recordingTLSConn struct {
	net.Conn
	record func([]byte)
}

func (c recordingTLSConn) Write(p []byte) (int, error) {
	c.record(bytes.Clone(p))
	return c.Conn.Write(p)
}

func TestSinkRealSDKMixedConnections(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	certs := certServer.TLS.Certificates
	certServer.Close()
	var capture bytes.Buffer
	encoder, err := pcapgo.NewNgWriter(&capture, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	var captureMu sync.Mutex
	timestamp := time.Unix(1700000000, 0)
	packet := func(port uint16, reverse, syn bool, seq uint32, payload []byte) {
		captureMu.Lock()
		defer captureMu.Unlock()
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(port), DstPort: 443, Seq: seq, SYN: syn, ACK: !syn || reverse, PSH: !syn, Window: 65535}
		if reverse {
			ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
			tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Error(err)
			return
		}
		ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Error(err)
			return
		}
		timestamp = timestamp.Add(time.Millisecond)
		if err := encoder.WritePacket(gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
			t.Error(err)
		}
	}
	// An established flow without a captured handshake must not poison others.
	packet(44000, false, true, 0, nil)
	packet(44000, false, false, 1, []byte{23, 3, 3, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	for i := range 3 {
		port := uint16(44001 + i)
		packet(port, false, true, 0, nil)
		packet(port, true, true, 0, nil)
		clientConn, serverConn := net.Pipe()
		deadline := time.Now().Add(5 * time.Second)
		_ = clientConn.SetDeadline(deadline)
		_ = serverConn.SetDeadline(deadline)
		clientSeq, serverSeq := uint32(1), uint32(1)
		clientWire := recordingTLSConn{Conn: clientConn, record: func(p []byte) { packet(port, false, false, clientSeq, p); clientSeq += uint32(len(p)) }}
		serverWire := recordingTLSConn{Conn: serverConn, record: func(p []byte) { packet(port, true, false, serverSeq, p); serverSeq += uint32(len(p)) }}
		var secrets bytes.Buffer
		client := tls.Client(clientWire, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, KeyLogWriter: &secrets})
		server := tls.Server(serverWire, &tls.Config{Certificates: certs, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
		serverDone := make(chan error, 1)
		go func() {
			if err := server.Handshake(); err != nil {
				serverDone <- err
				return
			}
			buf := make([]byte, 7)
			if _, err := io.ReadFull(server, buf); err != nil {
				serverDone <- err
				return
			}
			_, err := server.Write([]byte("healthy-response"))
			serverDone <- err
		}()
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, make([]byte, len("healthy-response"))); err != nil {
			t.Fatal(err)
		}
		if err := <-serverDone; err != nil {
			t.Fatal(err)
		}
		_ = clientConn.Close()
		_ = serverConn.Close()
		// First real connection has no keys; the next two have late DSBs.
		if i > 0 {
			if err := encoder.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, secrets.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := encoder.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plain")
	var logs bytes.Buffer
	s, err := NewSink(path, "", nil, nil, types.DecryptOptions{RawChunks: true, OnDiagnostic: diagnosticLogger(logger.New(&logs, true))})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.Write(capture.Bytes()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(data, []byte(hex.EncodeToString([]byte("healthy-response")))) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("healthy connections did not decrypt while stream remained open")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-s.done:
		t.Fatal("connection failure terminated active stream")
	default:
	}
	if s.Err() != nil {
		t.Fatal("connection failure became terminal")
	}
	// v1.4.3 returns an untyped history of failed connections at EOF. It cannot
	// safely be separated from pipeline errors; this integration conservatively
	// reports it at shutdown, without treating the active stream as broken.
	_ = s.Close()
	if bytes.Contains(logs.Bytes(), []byte("healthy-response")) {
		t.Fatal("plaintext leaked into diagnostics")
	}
}

func TestSinkRealSDKKeylogResourceLimit(t *testing.T) {
	var input bytes.Buffer
	encoder, err := pcapgo.NewNgWriter(&input, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	// An overlong synthetic comment exercises the real import limit without
	// allocating a large key cache or retaining real secrets.
	if err := encoder.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, append([]byte("#"), bytes.Repeat([]byte{'x'}, 8192)...)); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Flush(); err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 1)
	sink, err := newSink(context.Background(), func(err error) { failures <- err }, filepath.Join(t.TempDir(), "plain"), "", nil, nil, types.DecryptOptions{}, decryptor.DecryptPcapngStreamWithOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	_, _ = sink.Write(input.Bytes())
	select {
	case terminal := <-failures:
		if !errors.Is(terminal, sdkcrypto.ErrKeyLogResourceLimit) {
			t.Fatalf("lost SDK resource cause: %v", terminal)
		}
		if !strings.Contains(terminal.Error(), "keylog import resource limit exceeded") || len(terminal.Error()) > 200 {
			t.Fatal("missing bounded resource diagnostic")
		}
	case <-time.After(time.Second):
		t.Fatal("resource failure was not propagated")
	}
}

func TestSinkFailureDuringConcurrentDeliveryAndClose(t *testing.T) {
	root := errors.New("SDK failure during shutdown")
	var failures atomic.Int64
	s, err := newSink(context.Background(), func(error) { failures.Add(1) }, filepath.Join(t.TempDir(), "plain"), "", nil, nil, types.DecryptOptions{},
		func(_ context.Context, input io.ReadCloser, _ func(*types.DecryptedPacket) error, _ types.DecryptOptions) error {
			_, _ = io.Copy(io.Discard, input)
			return root
		})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 64 {
		wg.Go(func() {
			<-start
			for range 100 {
				_, _ = s.Write([]byte("synthetic input"))
				_ = s.Flush()
			}
		})
	}
	for range 8 {
		wg.Go(func() {
			<-start
			if err := s.Close(); !errors.Is(err, root) {
				t.Error("shutdown lost SDK root cause")
			}
		})
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent delivery/close deadlocked")
	}
	if failures.Load() != 1 {
		t.Fatal("terminal failure not reported exactly once")
	}
}
