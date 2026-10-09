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

package ecaptureq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/gojue/ecapture/v2/internal/domain"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
)

func newQueueClient(server *Server, size int) *Client {
	return &Client{
		hub:  server.hub,
		send: make(chan []byte, size),
		done: make(chan struct{}),
	}
}

func decodeEntry(t *testing.T, data []byte) *pb.LogEntry {
	t.Helper()
	entry := &pb.LogEntry{}
	if err := proto.Unmarshal(data, entry); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	return entry
}

func TestTypedPublishersKeepProcessLogsAndEventsSeparate(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	t.Cleanup(func() { _ = server.Close() })
	client := newQueueClient(server, 8)
	if err := server.hub.registerClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}

	if err := server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "probe initialized"}); err != nil {
		t.Fatal(err)
	}
	logEntry := decodeEntry(t, <-client.send)
	if logEntry.GetLogType() != pb.LogType_LOG_TYPE_PROCESS_LOG || logEntry.GetRunLog() != "probe initialized" {
		t.Fatalf("process log entry = %#v", logEntry)
	}

	const secret = "CLIENT_RANDOM secret-material"
	if err := server.PublishEvent(context.Background(), domain.CapturedEventEnvelope{
		Timestamp:       time.Unix(100, 0),
		UUID:            "event-1",
		EventType:       domain.EventTypeOutput,
		Format:          domain.CaptureFormatKeylog,
		Sensitivity:     domain.SensitivitySensitive,
		PID:             42,
		ProcessName:     "curl",
		SourceIP:        "127.0.0.1",
		SourcePort:      1234,
		DestinationIP:   "127.0.0.2",
		DestinationPort: 443,
		Direction:       "write",
		Payload:         []byte(secret),
		OriginalLength:  uint32(len(secret)),
		StreamID:        "stream-1",
		Sequence:        9,
	}); err != nil {
		t.Fatal(err)
	}
	eventEntry := decodeEntry(t, <-client.send)
	if eventEntry.GetLogType() != pb.LogType_LOG_TYPE_EVENT {
		t.Fatalf("event log type = %v", eventEntry.GetLogType())
	}
	event := eventEntry.GetEventPayload()
	if event == nil || event.GetCaptureFormat() != pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG ||
		event.GetSensitivity() != pb.Sensitivity_SENSITIVITY_SENSITIVE || string(event.GetPayload()) != secret {
		t.Fatalf("event payload = %#v", event)
	}
	if logEntry.GetRunLog() == secret {
		t.Fatal("captured secret leaked into PROCESS_LOG")
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
		if entry.GetLogType() != pb.LogType_LOG_TYPE_PROCESS_LOG {
			t.Fatalf("history entry %d type = %v", i, entry.GetLogType())
		}
		want := fmt.Sprintf("log-%03d", i+12)
		if entry.GetRunLog() != want {
			t.Fatalf("history entry %d = %q, want %q", i, entry.GetRunLog(), want)
		}
	}
	select {
	case extra := <-client.send:
		t.Fatalf("history exceeded %d entries: %v", LogBuffLen, decodeEntry(t, extra))
	default:
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
	if !errors.Is(err, ErrBackpressure) {
		t.Fatalf("PublishLog() error = %v, want ErrBackpressure", err)
	}
	if server.DroppedMessages() == 0 {
		t.Fatal("backpressure did not increment loss counter")
	}
}

func TestLiveWebSocketGetsFirstProcessLog(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	serveErrors, err := server.StartAsync()
	if err != nil {
		t.Fatal(err)
	}
	server.httpMu.Lock()
	address := server.listener.Addr().String()
	server.httpMu.Unlock()
	conn, err := websocket.Dial("ws://"+address+"/", "", "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// The immediate heartbeat proves registration and the single writer pump are live.
	var data []byte
	if err = websocket.Message.Receive(conn, &data); err != nil {
		t.Fatal(err)
	}
	if got := decodeEntry(t, data).GetLogType(); got != pb.LogType_LOG_TYPE_HEARTBEAT {
		t.Fatalf("first message type = %v", got)
	}
	if err = server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "live"}); err != nil {
		t.Fatal(err)
	}
	if err = websocket.Message.Receive(conn, &data); err != nil {
		t.Fatal(err)
	}
	entry := decodeEntry(t, data)
	if entry.GetLogType() != pb.LogType_LOG_TYPE_PROCESS_LOG || entry.GetRunLog() != "live" {
		t.Fatalf("live entry = %#v", entry)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	if err = server.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err = <-serveErrors; err != nil {
		t.Fatalf("serve error = %v", err)
	}
}

func TestConcurrentPublishAndShutdown(t *testing.T) {
	server := NewServer("127.0.0.1:0", io.Discard)
	client := newQueueClient(server, 1024)
	if err := server.hub.registerClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	const publishers = 16
	var wg sync.WaitGroup
	for i := 0; i < publishers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for sequence := 0; sequence < 32; sequence++ {
				_ = server.PublishLog(context.Background(), domain.OperationalLogRecord{Message: fmt.Sprintf("%d-%d", index, sequence)})
			}
		}(i)
	}
	wg.Wait()
	var closeWG sync.WaitGroup
	for i := 0; i < publishers; i++ {
		closeWG.Add(1)
		go func() {
			defer closeWG.Done()
			_ = server.Close()
		}()
	}
	closeWG.Wait()
}
