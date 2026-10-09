// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
)

var (
	server = flag.String("server", "", "eCaptureQ WebSocket URL")
	format = flag.String("format", "text", "required capture format")
	token  = flag.String("token", "", "required text payload token")
	wait   = flag.Duration("timeout", 20*time.Second, "overall timeout")
)

func main() {
	flag.Parse()
	deadline := time.Now().Add(*wait)
	var conn *websocket.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = websocket.Dial(*server, "", "http://localhost/")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fatalf("connect: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	wantFormat, err := parseFormat(*format)
	if err != nil {
		fatalf("%v", err)
	}
	var processLog, event bool
	for time.Now().Before(deadline) {
		var data []byte
		if err := websocket.Message.Receive(conn, &data); err != nil {
			fatalf("receive before requirements were met: %v", err)
		}
		entry := &pb.LogEntry{}
		if err := proto.Unmarshal(data, entry); err != nil {
			fatalf("decode protobuf: %v", err)
		}
		switch entry.GetLogType() {
		case pb.LogType_LOG_TYPE_PROCESS_LOG:
			if entry.GetRunLog() == "" {
				fatalf("PROCESS_LOG payload is empty")
			}
			processLog = true
			if *token != "" && strings.Contains(entry.GetRunLog(), *token) {
				fatalf("captured token leaked into PROCESS_LOG")
			}
		case pb.LogType_LOG_TYPE_EVENT:
			captured := entry.GetEventPayload()
			if captured == nil || captured.GetCaptureFormat() != wantFormat {
				continue
			}
			if err := validateEvent(captured, wantFormat); err != nil {
				fatalf("invalid EVENT metadata: %v", err)
			}
			if *token == "" || strings.Contains(string(captured.GetPayload()), *token) {
				event = true
			}
		}
		if processLog && event {
			fmt.Printf("PROCESS_LOG=1 EVENT=1 FORMAT=%s METADATA=1\n", wantFormat.String())
			return
		}
	}
	fatalf("timed out: PROCESS_LOG=%v EVENT=%v", processLog, event)
}

func validateEvent(event *pb.Event, wantFormat pb.CaptureFormat) error {
	if event.GetTimestamp() == 0 {
		return fmt.Errorf("timestamp is zero")
	}
	if event.GetSequence() == 0 {
		return fmt.Errorf("sequence is zero")
	}
	if event.GetLength() == 0 || int(event.GetLength()) != len(event.GetPayload()) {
		return fmt.Errorf("length=%d payload=%d", event.GetLength(), len(event.GetPayload()))
	}
	if event.GetOriginalLength() < event.GetLength() {
		return fmt.Errorf("original_length=%d length=%d", event.GetOriginalLength(), event.GetLength())
	}
	wantSensitivity := pb.Sensitivity_SENSITIVITY_NORMAL
	if wantFormat != pb.CaptureFormat_CAPTURE_FORMAT_TEXT {
		wantSensitivity = pb.Sensitivity_SENSITIVITY_SENSITIVE
	}
	if event.GetSensitivity() != wantSensitivity {
		return fmt.Errorf("sensitivity=%s want=%s", event.GetSensitivity(), wantSensitivity)
	}
	return nil
}

func parseFormat(value string) (pb.CaptureFormat, error) {
	switch value {
	case "text":
		return pb.CaptureFormat_CAPTURE_FORMAT_TEXT, nil
	case "keylog":
		return pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, nil
	case "pcapng":
		return pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, nil
	default:
		return pb.CaptureFormat_CAPTURE_FORMAT_UNSPECIFIED, fmt.Errorf("unsupported format %q", value)
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
