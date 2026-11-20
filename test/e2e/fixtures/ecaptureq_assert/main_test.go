// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
	"github.com/gorilla/websocket"
)

func TestExtractionCanContainOnlyOperationalLogs(t *testing.T) {
	state := &assertionState{allowNoEvents: true, requireSensitive: true, logOutput: io.Discard, eventOutput: io.Discard}
	if state.satisfied() {
		t.Fatal("empty file accepted")
	}
	if err := state.consume(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_PROCESS_LOG, Payload: &pb.LogEntry_RunLog{RunLog: "unsupported protocol"}}); err != nil {
		t.Fatal(err)
	}
	if !state.satisfied() {
		t.Fatal("valid zero-event diagnostic was rejected")
	}
	state.allowNoEvents = false
	if state.satisfied() {
		t.Fatal("online capture assertions accepted no events")
	}
}

func TestSubscriptionFramesAndCompletion(t *testing.T) {
	for _, tt := range []struct {
		name        string
		messageType int
		payload     []byte
		wantEOF     bool
		wantError   bool
	}{
		{"binary", websocket.BinaryMessage, []byte("payload"), false, false},
		{"text", websocket.TextMessage, []byte("payload"), false, true},
		{"normal close", websocket.CloseMessage, websocket.FormatCloseMessage(1000, ""), true, false},
		{"producer failure", websocket.CloseMessage, websocket.FormatCloseMessage(1011, ""), false, true},
		{"abrupt disconnect", 0, nil, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upgrader := websocket.Upgrader{Subprotocols: []string{protocol.Subprotocol}, CheckOrigin: func(*http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				if tt.messageType != 0 {
					if err := conn.WriteMessage(tt.messageType, tt.payload); err != nil {
						t.Error(err)
					}
				}
			}))
			defer server.Close()
			deadline := time.Now().Add(5 * time.Second)
			conn, err := dialSubscription("ws"+strings.TrimPrefix(server.URL, "http"), deadline)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(deadline)
			data, err := readBinaryMessage(conn)
			if errors.Is(err, io.EOF) != tt.wantEOF {
				t.Fatalf("EOF=%v, want %v (error=%v)", errors.Is(err, io.EOF), tt.wantEOF, err)
			}
			if !tt.wantEOF && (err != nil) != tt.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tt.wantError)
			}
			if !tt.wantEOF && !tt.wantError && !bytes.Equal(data, tt.payload) {
				t.Fatalf("payload=%q", data)
			}
		})
	}
}

func TestSubscriptionRequiresV2Subprotocol(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer server.Close()
	conn, err := dialSubscription("ws"+strings.TrimPrefix(server.URL, "http"), time.Now().Add(5*time.Second))
	if conn != nil || err == nil || !strings.Contains(err.Error(), protocol.Subprotocol) {
		t.Fatalf("unnegotiated protocol accepted: conn=%v error=%v", conn, err)
	}
}

func TestValidateProcess(t *testing.T) {
	const expected = int64(2341289)
	for _, tt := range []struct {
		name      string
		pid       int64
		process   string
		args      string
		truncated bool
		wantError bool
	}{
		{"kernel TGID", expected, "openssl_client", "client\x00private-token\x00", false, false},
		{"namespace PID", 14287, "openssl_client", "client\x00private-token\x00", false, true},
		{"unknown PID", 0, "openssl_client", "client\x00private-token\x00", false, true},
		{"unknown name", expected, "", "client\x00private-token\x00", false, true},
		{"placeholder name", expected, "decryptor", "client\x00private-token\x00", false, true},
		{"missing argv", expected, "openssl_client", "", false, true},
		{"wrong argv", expected, "openssl_client", "client\x00different-secret\x00", false, true},
		{"truncated argv", expected, "openssl_client", "client\x00private-token\x00", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProcess(&pb.TextEvent{Pid: tt.pid, Pname: tt.process, ProcessArgs: []byte(tt.args), ProcessArgsTruncated: tt.truncated}, expected, "private-token")
			if (err != nil) != tt.wantError {
				t.Fatalf("validateProcess error=%v, wantError=%v", err, tt.wantError)
			}
			if err != nil && (strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "different-secret")) {
				t.Fatal("diagnostic leaked argv")
			}
		})
	}
	if err := validateProcess(&pb.TextEvent{Pid: 0, Pname: "openssl_client"}, 0, ""); err == nil {
		t.Fatal("zero expected PID must fail")
	}
}

func TestTextFormattingPreservesOriginalLength(t *testing.T) {
	payload := []byte("[request] 61 62 63")
	text := &pb.TextEvent{Timestamp: 1, Sequence: 1, Payload: payload, Length: uint32(len(payload)), OriginalLength: 3}
	event := &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_TEXT, Content: &pb.Event_Text{Text: text}}
	if err := validateEvent(event, pb.CaptureFormat_CAPTURE_FORMAT_TEXT, false); err != nil {
		t.Fatalf("formatted text with original byte length was rejected: %v", err)
	}
	text.Length++
	if err := validateEvent(event, pb.CaptureFormat_CAPTURE_FORMAT_TEXT, false); err == nil {
		t.Fatal("payload length mismatch was accepted")
	}
}

func TestJSONLinesRejectsIncompleteTail(t *testing.T) {
	for _, input := range []string{`{"log_type":"LOG_TYPE_PROCESS_LOG"}`, "{\"run_log\":\"ok\"}\n{\"run_log\":"} {
		next := jsonLines(strings.NewReader(input))
		var err error
		for err == nil {
			_, err = next()
		}
		if err == io.EOF {
			t.Fatal("incomplete final line accepted")
		}
	}
	next := jsonLines(strings.NewReader("{}\n{}\n"))
	for i := 0; i < 2; i++ {
		if _, err := next(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := next(); err != io.EOF {
		t.Fatalf("unexpected end: %v", err)
	}
}

func TestLogsOnlyRejectsEveryEvent(t *testing.T) {
	state := &assertionState{logsOnly: true, logOutput: io.Discard, eventOutput: io.Discard}
	logEntry := &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_PROCESS_LOG, Payload: &pb.LogEntry_RunLog{RunLog: "started"}}
	if err := state.consume(logEntry); err != nil {
		t.Fatal(err)
	}
	if !state.satisfied() {
		t.Fatal("valid operational log was not observed")
	}
	for _, format := range []pb.CaptureFormat{pb.CaptureFormat_CAPTURE_FORMAT_TEXT, pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG} {
		event := &pb.Event{CaptureFormat: format}
		switch format {
		case pb.CaptureFormat_CAPTURE_FORMAT_TEXT:
			event.Content = &pb.Event_Text{Text: &pb.TextEvent{}}
		case pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG:
			event.Content = &pb.Event_Keylog{Keylog: &pb.KeylogEvent{Data: []byte("x")}}
		case pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG:
			event.Content = &pb.Event_Pcapng{Pcapng: &pb.PcapngEvent{Data: []byte("x")}}
		}
		if err := state.consume(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT, Payload: &pb.LogEntry_EventPayload{EventPayload: event}}); err == nil {
			t.Fatalf("logs-only accepted %s", format)
		}
	}
}

func TestNativeKeylogNeedsActualRecords(t *testing.T) {
	valid := []byte("CLIENT_RANDOM " + strings.Repeat("01", 32) + " " + strings.Repeat("02", 48) + "\n")
	for _, input := range [][]byte{nil, []byte("Label:CLIENT_RANDOM ClientRandom:abcd"), valid[:len(valid)-1]} {
		if nativeReady(pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, input) {
			t.Fatal("incomplete or summary-only keylog accepted")
		}
	}
	if !nativeReady(pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, valid) {
		t.Fatal("valid NSS keylog rejected")
	}
}

func TestNativePcapngRequiresPacketsAndRealDSB(t *testing.T) {
	block := func(kind uint32, body []byte) []byte {
		padded := (len(body) + 3) &^ 3
		out := make([]byte, padded+12)
		binary.LittleEndian.PutUint32(out[:4], kind)
		binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
		copy(out[8:], body)
		binary.LittleEndian.PutUint32(out[len(out)-4:], uint32(len(out)))
		return out
	}
	shb := make([]byte, 16)
	binary.LittleEndian.PutUint32(shb, 0x1a2b3c4d)
	data := block(0x0a0d0d0a, shb)
	data = append(data, block(1, make([]byte, 8))...)
	packet := make([]byte, 24)
	binary.LittleEndian.PutUint32(packet[12:], 4)
	data = append(data, block(6, packet)...)
	if nativeReady(pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, data) {
		t.Fatal("pcapng without DSB accepted")
	}
	keys := []byte("CLIENT_RANDOM " + strings.Repeat("01", 32) + " " + strings.Repeat("02", 48) + "\n")
	dsb := make([]byte, 8)
	binary.LittleEndian.PutUint32(dsb, 0x544c534b)
	binary.LittleEndian.PutUint32(dsb[4:], uint32(len(keys)))
	data = append(data, block(10, append(dsb, keys...))...)
	if !nativeReady(pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, data) {
		t.Fatal("pcapng with packet and valid DSB rejected")
	}
	if nativeReady(pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, data[:len(data)-1]) {
		t.Fatal("truncated block accepted")
	}
	if nativeReady(pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, bytes.ReplaceAll(data, []byte("CLIENT_RANDOM"), []byte("invalid!!!!!"))) {
		t.Fatal("invalid DSB accepted")
	}
}

func TestNativeFragmentsAreExtractedWithoutLogBytes(t *testing.T) {
	var events, logs bytes.Buffer
	state := &assertionState{wantFormat: pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, eventOutput: &events, logOutput: &logs, process: true}
	data := []byte("CLIENT_RANDOM " + strings.Repeat("01", 32) + " " + strings.Repeat("02", 48) + "\n")
	for _, fragment := range [][]byte{data[:7], data[7:]} {
		entry := &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT, Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, Content: &pb.Event_Keylog{Keylog: &pb.KeylogEvent{Data: fragment}}}}}
		if err := state.consume(entry); err != nil {
			t.Fatal(err)
		}
		if err := state.consume(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_PROCESS_LOG, Payload: &pb.LogEntry_RunLog{RunLog: "runtime"}}); err != nil {
			t.Fatal(err)
		}
	}
	if !state.satisfied() || !bytes.Equal(events.Bytes(), data) || strings.Contains(events.String(), "runtime") {
		t.Fatal("native extraction lost bytes or mixed operational logs")
	}
}
