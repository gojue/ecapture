// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gojue/ecapture/v2/internal/domain"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
)

func TestConsoleLabelsEveryLineWithoutTerminalControls(t *testing.T) {
	var buf bytes.Buffer
	p := NewConsolePublisher("stdout", &buf)
	ctx := context.Background()
	if err := p.PublishLog(ctx, domain.OperationalLogRecord{Module: "tls", Message: `{"level":"info","message":"started\nready"}`}); err != nil {
		t.Fatal(err)
	}
	if err := p.PublishEvent(ctx, domain.CapturedEventEnvelope{Module: "tls", Format: domain.CaptureFormatText, Payload: []byte("HTTP/1.1\n\x1b[2Jbody\n")}); err != nil {
		t.Fatal(err)
	}
	if err := p.PublishEvent(ctx, domain.CapturedEventEnvelope{Module: "tls", Format: domain.CaptureFormatPcapng, Payload: []byte{0, 1, 2}}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("physical lines = %d", len(lines))
	}
	for i, line := range lines {
		kind := "event"
		if i < 2 {
			kind = "log"
		}
		if !strings.HasPrefix(line, "[log_type="+kind+" ") {
			t.Fatalf("unclassified line: %q", line)
		}
	}
	if strings.ContainsRune(buf.String(), '\x1b') || !strings.Contains(buf.String(), `\x1b[2Jbody`) || !strings.Contains(lines[4], "encoded_bytes=3") {
		t.Fatalf("unsafe or binary console output: %q", buf.String())
	}
}

func TestConsoleSerializesConcurrentRecords(t *testing.T) {
	var buf bytes.Buffer
	p := NewConsolePublisher("stderr", &buf)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: domain.CaptureFormatKeylog, Payload: []byte("first\nsecond\n")}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if strings.Count(buf.String(), "[log_type=event capture_format=keylog ") != 100 {
		t.Fatal("concurrent records interleaved or lost")
	}
}

type recordSink struct {
	bytes.Buffer
	short  bool
	closed int
}

func (s *recordSink) Name() string { return "records" }
func (s *recordSink) Flush() error { return nil }
func (s *recordSink) Close() error { s.closed++; return nil }
func (s *recordSink) Write(p []byte) (int, error) {
	if s.short {
		return s.Buffer.Write(p[:len(p)-1])
	}
	return s.Buffer.Write(p)
}

func TestJSONRecordsRoundTripAllFormats(t *testing.T) {
	sink := &recordSink{}
	p, err := NewJSONPublisher(sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.PublishLog(context.Background(), domain.OperationalLogRecord{Module: "gotls", Message: "ready\nnow"}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []domain.CaptureFormat{domain.CaptureFormatText, domain.CaptureFormatKeylog, domain.CaptureFormatPcapng} {
		if err := p.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Module: "gotls", Format: format, Payload: []byte{0, '\n', 255}, Timestamp: time.Unix(123, 0), ProcessArgs: []byte("a\x00b"), TLS: map[string]string{"version": "1.3"}}); err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.Split(bytes.TrimSpace(sink.Bytes()), []byte("\n"))
	if len(lines) != 4 {
		t.Fatalf("JSON lines = %d", len(lines))
	}
	for i, line := range lines {
		entry := &pb.LogEntry{}
		if err := protojson.Unmarshal(line, entry); err != nil {
			t.Fatal(err)
		}
		if err := protocol.ValidateLogEntry(entry); err != nil {
			t.Fatal(err)
		}
		if entry.Module != "gotls" {
			t.Fatal("module lost")
		}
		var data []byte
		switch i {
		case 0:
			if entry.LogType != pb.LogType_LOG_TYPE_PROCESS_LOG || entry.GetRunLog() != "ready\nnow" {
				t.Fatal("log/event classification lost")
			}
			continue
		case 1:
			data = entry.GetEventPayload().GetText().GetPayload()
			if string(entry.GetEventPayload().GetText().GetProcessArgs()) != "a\x00b" {
				t.Fatal("argv lost")
			}
		case 2:
			data = entry.GetEventPayload().GetKeylog().GetData()
		case 3:
			data = entry.GetEventPayload().GetPcapng().GetData()
		}
		if !bytes.Equal(data, []byte{0, '\n', 255}) {
			t.Fatal("native bytes changed in JSON encoding")
		}
	}
}

func TestJSONFailureLatchesAndClosesOnce(t *testing.T) {
	sink := &recordSink{short: true}
	p, err := NewJSONPublisher(sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "first"}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	size := sink.Len()
	if err := p.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "later"}); !errors.Is(err, io.ErrShortWrite) || sink.Len() != size {
		t.Fatal("continued writing after corrupting a record")
	}
	for range 2 {
		if err := p.Close(); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("close lost failure: %v", err)
		}
	}
	if sink.closed != 1 {
		t.Fatal("sink closed more than once")
	}
}
