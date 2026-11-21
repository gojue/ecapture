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

package stream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/gojue/ecapture/v2/internal/domain"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
)

func newQueueClient(server *Server, size int) *Client {
	return &Client{hub: server.hub, send: make(chan []byte, size), done: make(chan struct{})}
}

func decodeEntry(t *testing.T, data []byte) *pb.LogEntry {
	t.Helper()
	entry := &pb.LogEntry{}
	if err := proto.Unmarshal(data, entry); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ValidateLogEntry(entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

func startServer(t *testing.T, format domain.CaptureFormat, path string) (*Server, string) {
	t.Helper()
	server := NewServerWithPath("127.0.0.1:0", path, io.Discard)
	if err := server.BeginCapture(format, "tls", "lo", "", nil); err != nil {
		t.Fatal(err)
	}
	serving, err := server.StartAsync()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-serving:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("listener did not stop")
		}
	})
	server.httpMu.Lock()
	addr := server.listener.Addr().String()
	server.httpMu.Unlock()
	return server, addr
}

func dialSubscriber(t *testing.T, addr, path string) *websocket.Conn {
	t.Helper()
	conn, err := websocket.Dial("ws://"+addr+path, protocol.Subprotocol, "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	entry := receiveEntry(t, conn)
	if entry.GetLogType() != pb.LogType_LOG_TYPE_HEARTBEAT || entry.GetModule() != "tls" {
		t.Fatalf("first entry = %v", entry)
	}
	return conn
}

func receiveEntry(t *testing.T, conn *websocket.Conn) *pb.LogEntry {
	t.Helper()
	var data []byte
	if err := websocket.Message.Receive(conn, &data); err != nil {
		t.Fatal(err)
	}
	return decodeEntry(t, data)
}

func TestTypedPublishersKeepProcessLogsAndEventsSeparate(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	t.Cleanup(func() { _ = server.Close() })
	if err := server.BeginCapture(domain.CaptureFormatText, "tls", "", "", nil); err != nil {
		t.Fatal(err)
	}
	client := newQueueClient(server, 8)
	if err := server.hub.registerClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "probe initialized"}); err != nil {
		t.Fatal(err)
	}
	log := decodeEntry(t, <-client.send)
	if log.GetLogType() != pb.LogType_LOG_TYPE_PROCESS_LOG || log.GetModule() != "tls" {
		t.Fatal(log)
	}
	payload := []byte("captured application message")
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{
		Timestamp: time.Unix(100, 0), UUID: "event-1", Format: domain.CaptureFormatText,
		Sensitivity: domain.SensitivitySensitive, PID: 42, ProcessName: "curl",
		ProcessArgs: []byte("curl\x00" + strings.Repeat("\xff", 251)), ProcessArgsTruncated: true,
		TLS: map[string]string{"version": "TLS 1.3", "ja3": "fingerprint"}, Payload: payload, OriginalLength: uint32(len(payload)),
	}); err != nil {
		t.Fatal(err)
	}
	entry := decodeEntry(t, <-client.send)
	event := entry.GetEventPayload().GetText()
	if entry.GetModule() != "tls" || event.GetPid() != 42 || event.GetPname() != "curl" || event.GetTls()["ja3"] != "fingerprint" {
		t.Fatal(entry)
	}
	if !event.GetProcessArgsTruncated() || len(event.GetProcessArgs()) != 256 || !bytes.Equal(event.GetPayload(), payload) {
		t.Fatal(event)
	}
	if strings.Contains(log.GetRunLog(), string(payload)) {
		t.Fatal("event leaked into process log")
	}
}

func TestKeylogPublishesCanonicalBytes(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	t.Cleanup(func() { _ = server.Close() })
	client := newQueueClient(server, 8)
	if err := server.hub.registerClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	data := []byte("CLIENT_RANDOM " + strings.Repeat("01", 32) + " " + strings.Repeat("02", 48) + "\n")
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatKeylog, Payload: data}); err != nil {
		t.Fatal(err)
	}
	entry := decodeEntry(t, <-client.send)
	if !bytes.Equal(entry.GetEventPayload().GetKeylog().GetData(), data) {
		t.Fatal("keylog bytes changed")
	}
}

func TestOperationalHistoryIsBoundedAndExcludesEvents(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	t.Cleanup(func() { _ = server.Close() })
	for i := 0; i < LogBuffLen+12; i++ {
		if err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: fmt.Sprintf("log-%03d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatText, Payload: []byte("captured")}); err != nil {
		t.Fatal(err)
	}
	client := newQueueClient(server, LogBuffLen)
	if err := server.hub.registerClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < LogBuffLen; i++ {
		entry := decodeEntry(t, <-client.send)
		if entry.GetLogType() != pb.LogType_LOG_TYPE_PROCESS_LOG || entry.GetRunLog() != fmt.Sprintf("log-%03d", i+12) {
			t.Fatal(entry)
		}
	}
	select {
	case <-client.send:
		t.Fatal("history exceeded limit")
	default:
	}
}

func TestCollectorInfoSurvivesLogRotationAndReplaysCurrentSnapshot(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	t.Cleanup(func() { _ = server.Close() })
	publish := func(message string) {
		t.Helper()
		if err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: message}); err != nil {
			t.Fatal(err)
		}
	}
	publish(`{"event":"collector_info","schemaVersion":1,"collector":{"module":"gotls","mode":"text"}}`)
	for i := 0; i < LogBuffLen+10; i++ {
		publish(fmt.Sprintf("log-%d", i))
	}
	current := `{"event":"collector_info","schemaVersion":1,"collector":{"module":"gotls","mode":"keylog"}}`
	publish(current)
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatKeylog, Payload: []byte("secret\n")}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		client := newQueueClient(server, LogBuffLen+2)
		if err := server.hub.registerClient(context.Background(), client); err != nil {
			t.Fatal(err)
		}
		data := <-client.send
		entry := decodeEntry(t, data)
		if entry.GetModule() != "gotls" || entry.GetLogType() != pb.LogType_LOG_TYPE_PROCESS_LOG || entry.GetRunLog() != current {
			t.Fatalf("metadata was not first/current: %v", entry)
		}
		// A subscriber must not own the retained backing slice.
		data[0] ^= 0xff
		for i := 0; i < LogBuffLen; i++ {
			if entry := decodeEntry(t, <-client.send); entry.GetRunLog() != fmt.Sprintf("log-%d", i+10) {
				t.Fatal("unexpected replay", entry)
			}
		}
		if len(client.send) != 0 {
			t.Fatal("retained history replayed captured data or stale metadata")
		}
		server.hub.unregisterClient(client)
	}
}

func TestCollectorInfoPrecedesLiveEvents(t *testing.T) {
	server, addr := startServer(t, domain.CaptureFormatText, "/")
	metadata := `{"event":"collector_info","schemaVersion":1,"collector":{"module":"tls","version":"test"}}`
	if err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: metadata}); err != nil {
		t.Fatal(err)
	}
	conn := dialSubscriber(t, addr, "/")
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatText, Payload: []byte("live")}); err != nil {
		t.Fatal(err)
	}
	if got := receiveEntry(t, conn); got.GetRunLog() != metadata {
		t.Fatalf("metadata missing before live event: %v", got)
	}
	if got := receiveEntry(t, conn); string(got.GetEventPayload().GetText().GetPayload()) != "live" {
		t.Fatal(got)
	}
}

func TestCollectorInfoMarkerIsBoundedAndExplicit(t *testing.T) {
	for _, message := range []string{
		`{"message":"collector_info","collector":{}}`,
		`{"event":"collector_info","schemaVersion":2,"collector":{}}`,
		`{"event":"collector_info","schemaVersion":1,"collector":null}`,
		`{"event":"collector_info","schemaVersion":1,"collector":{}}` + strings.Repeat(" ", 256<<10),
	} {
		if _, ok := collectorInfoModule(message); ok {
			t.Fatal("invalid metadata retained")
		}
	}
}

func TestBackpressureIsObservable(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	t.Cleanup(func() { _ = server.Close() })
	client := newQueueClient(server, 1)
	if err := server.hub.registerClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "first"}); err != nil {
		t.Fatal(err)
	}
	err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "second"})
	if !errors.Is(err, ErrBackpressure) || server.DroppedMessages() != 1 {
		t.Fatalf("error=%v, dropped=%d", err, server.DroppedMessages())
	}
	if client.graceful.Load() {
		t.Fatal("failed stream marked complete")
	}
}

func TestWebSocketRequiresV2AndExactPath(t *testing.T) {
	server, addr := startServer(t, domain.CaptureFormatText, "/events")
	for _, version := range []string{"", "ecapture.v1"} {
		conn, err := websocket.Dial("ws://"+addr+"/events", version, "http://localhost/")
		if err == nil {
			_ = conn.Close()
			t.Fatalf("accepted protocol %q", version)
		}
	}
	for _, path := range []string{"/", "/events/", "/events/child"} {
		response, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status=%d", path, response.StatusCode)
		}
	}
	conn := dialSubscriber(t, addr, "/events")
	if err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "live"}); err != nil {
		t.Fatal(err)
	}
	if entry := receiveEntry(t, conn); entry.GetRunLog() != "live" {
		t.Fatal(entry)
	}
}

func TestEndCaptureDrainsAndKeepsListener(t *testing.T) {
	server, addr := startServer(t, domain.CaptureFormatKeylog, "/")
	conn := dialSubscriber(t, addr, "/")
	for i := 0; i < 20; i++ {
		if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatKeylog, Payload: []byte(fmt.Sprintf("record-%d\n", i))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.EndCapture(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		entry := receiveEntry(t, conn)
		if got := string(entry.GetEventPayload().GetKeylog().GetData()); got != fmt.Sprintf("record-%d\n", i) {
			t.Fatalf("record %d=%q", i, got)
		}
	}
	var tail []byte
	if err := websocket.Message.Receive(conn, &tail); !errors.Is(err, io.EOF) {
		t.Fatalf("closed stream error=%v", err)
	}
	if _, err := websocket.Dial("ws://"+addr+"/", protocol.Subprotocol, "http://localhost/"); err == nil {
		t.Fatal("accepted connection between generations")
	}
	if err := server.BeginCapture(domain.CaptureFormatText, "tls", "", "", nil); err != nil {
		t.Fatal(err)
	}
	next := dialSubscriber(t, addr, "/")
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatText, Payload: []byte("new generation")}); err != nil {
		t.Fatal(err)
	}
	if got := string(receiveEntry(t, next).GetEventPayload().GetText().GetPayload()); got != "new generation" {
		t.Fatal(got)
	}
}

func receivePcapng(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	var result []byte
	for {
		var data []byte
		err := websocket.Message.Receive(conn, &data)
		if errors.Is(err, io.EOF) {
			return result
		}
		if err != nil {
			t.Fatal(err)
		}
		entry := decodeEntry(t, data)
		if entry.GetLogType() == pb.LogType_LOG_TYPE_EVENT {
			result = append(result, entry.GetEventPayload().GetPcapng().GetData()...)
		}
	}
}

func TestLatePcapngSubscribersHaveIndependentCompleteHeaders(t *testing.T) {
	server, addr := startServer(t, domain.CaptureFormatPcapng, "/")
	packet := func(value byte) domain.CapturedPacket {
		return domain.CapturedPacket{Data: bytes.Repeat([]byte{value}, 64), Timestamp: time.Unix(100, 0), PID: 42, ProcessName: "client"}
	}
	if err := server.PublishPacket(context.Background(), packet(0x11)); err != nil {
		t.Fatal(err)
	}
	if err := server.PublishKeylog(context.Background(), []byte("HISTORICAL_KEY\n")); err != nil {
		t.Fatal(err)
	}
	first := dialSubscriber(t, addr, "/")
	if err := server.PublishPacket(context.Background(), packet(0x22)); err != nil {
		t.Fatal(err)
	}
	second := dialSubscriber(t, addr, "/")
	if err := server.PublishPacket(context.Background(), packet(0x33)); err != nil {
		t.Fatal(err)
	}
	keylog := []byte("CLIENT_RANDOM " + strings.Repeat("01", 32) + " " + strings.Repeat("02", 48) + "\n")
	if err := server.PublishKeylog(context.Background(), keylog); err != nil {
		t.Fatal(err)
	}
	// Process-wide encoded bytes must never leak into independently encoded subscribers.
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatPcapng, Payload: []byte("CORRUPT_GLOBAL_STREAM")}); err != nil {
		t.Fatal(err)
	}
	if err := server.EndCapture(); err != nil {
		t.Fatal(err)
	}
	for i, conn := range []*websocket.Conn{first, second} {
		data := receivePcapng(t, conn)
		if !bytes.HasPrefix(data, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
			t.Fatal("missing SHB")
		}
		if !bytes.Contains(data, keylog) || bytes.Contains(data, []byte("HISTORICAL_KEY")) || bytes.Contains(data, []byte("CORRUPT_GLOBAL_STREAM")) {
			t.Fatal("incorrect native stream content")
		}
		reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		var packets [][]byte
		for {
			value, _, err := reader.ReadPacketData()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			packets = append(packets, value)
		}
		want := 2 - i
		if len(packets) != want {
			t.Fatalf("subscriber %d packets=%d want=%d", i, len(packets), want)
		}
		if !bytes.HasPrefix(packets[len(packets)-1], bytes.Repeat([]byte{0x33}, 64)) {
			t.Fatal("missing future packet")
		}
		if i == 0 && !bytes.HasPrefix(packets[0], bytes.Repeat([]byte{0x22}, 64)) {
			t.Fatal("first subscriber missed its earlier packet")
		}
	}
}

func TestConcurrentPublishAndShutdown(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	client := newQueueClient(server, 1024)
	if err := server.hub.registerClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for sequence := 0; sequence < 32; sequence++ {
				_ = server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: fmt.Sprintf("%d-%d", index, sequence)})
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = server.Close() }()
	}
	wg.Wait()
}

// x/net/websocket reports every peer close as io.EOF and hides its status code.
// Read the server wire frames directly so completion/partial semantics remain
// covered without adding another WebSocket dependency to the root module.
func TestCaptureCompletionCloseCodes(t *testing.T) {
	for _, aborted := range []bool{false, true} {
		t.Run(fmt.Sprintf("aborted=%v", aborted), func(t *testing.T) {
			server, addr := startServer(t, domain.CaptureFormatKeylog, "/events")
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, err = fmt.Fprintf(conn, "GET /events HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\nOrigin: http://localhost\r\n\r\n", addr, protocol.Subprotocol)
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Sec-WebSocket-Protocol") != protocol.Subprotocol {
				t.Fatalf("unexpected handshake %s", response.Status)
			}
			// Heartbeat establishes that registration is complete before publish.
			opcode, data := readServerFrame(t, reader)
			if opcode != websocket.BinaryFrame || decodeEntry(t, data).LogType != pb.LogType_LOG_TYPE_HEARTBEAT {
				t.Fatal("missing initial heartbeat")
			}
			keylog := []byte("CLIENT_RANDOM " + strings.Repeat("01", 32) + " " + strings.Repeat("02", 48) + "\n")
			if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatKeylog, Payload: keylog}); err != nil {
				t.Fatal(err)
			}
			if aborted {
				err = server.AbortCapture()
			} else {
				err = server.EndCapture()
			}
			if err != nil {
				t.Fatal(err)
			}
			opcode, data = readServerFrame(t, reader)
			if opcode != websocket.BinaryFrame || !bytes.Equal(decodeEntry(t, data).GetEventPayload().GetKeylog().GetData(), keylog) {
				t.Fatal("queued event was not drained before close")
			}
			opcode, data = readServerFrame(t, reader)
			want := uint16(1000)
			if aborted {
				want = 1011
			}
			if opcode != websocket.CloseFrame || len(data) < 2 || binary.BigEndian.Uint16(data) != want {
				t.Fatalf("close opcode=%d payload=%x want=%d", opcode, data, want)
			}
		})
	}
}

func readServerFrame(t *testing.T, reader io.Reader) (byte, []byte) {
	t.Helper()
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0]&0x80 == 0 || header[1]&0x80 != 0 {
		t.Fatal("fragmented or masked server frame")
	}
	size := uint64(header[1] & 0x7f)
	switch size {
	case 126:
		var value [2]byte
		if _, err := io.ReadFull(reader, value[:]); err != nil {
			t.Fatal(err)
		}
		size = uint64(binary.BigEndian.Uint16(value[:]))
	case 127:
		var value [8]byte
		if _, err := io.ReadFull(reader, value[:]); err != nil {
			t.Fatal(err)
		}
		size = binary.BigEndian.Uint64(value[:])
	}
	if size > 1<<20 {
		t.Fatal("unexpected large test frame")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatal(err)
	}
	return header[0] & 0xf, data
}
