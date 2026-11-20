// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func nativeEntry(format pb.CaptureFormat, data []byte) *pb.LogEntry {
	event := &pb.Event{CaptureFormat: format}
	if format == pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG {
		event.Content = &pb.Event_Keylog{Keylog: &pb.KeylogEvent{Data: data}}
	} else {
		event.Content = &pb.Event_Pcapng{Pcapng: &pb.PcapngEvent{Data: data}}
	}
	return &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT, Module: "tls", Payload: &pb.LogEntry_EventPayload{EventPayload: event}}
}

func syntheticKeylog() []byte {
	return []byte("CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 48) + "\n")
}

func syntheticPcapng() []byte {
	block := func(kind uint32, body []byte) []byte {
		data := make([]byte, 12+len(body))
		binary.LittleEndian.PutUint32(data[:4], kind)
		binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)))
		copy(data[8:], body)
		binary.LittleEndian.PutUint32(data[len(data)-4:], uint32(len(data)))
		return data
	}
	section := make([]byte, 16)
	binary.LittleEndian.PutUint32(section, 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(section[4:], 1)
	binary.LittleEndian.PutUint64(section[8:], ^uint64(0))
	iface := make([]byte, 8)
	binary.LittleEndian.PutUint16(iface, 1)
	binary.LittleEndian.PutUint32(iface[4:], 65535)
	packet := make([]byte, 24)
	binary.LittleEndian.PutUint32(packet[12:], 4)
	binary.LittleEndian.PutUint32(packet[16:], 4)
	copy(packet[20:], []byte{1, 2, 3, 4})
	return append(append(block(0x0a0d0d0a, section), block(1, iface)...), block(6, packet)...)
}

func TestReceiverNativeFragmentsExcludeOperationalRecords(t *testing.T) {
	for _, format := range []pb.CaptureFormat{pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG} {
		t.Run(format.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture")
			var console bytes.Buffer
			r := &messageReceiver{output: &console}
			data := syntheticKeylog()
			if format == pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG {
				data = syntheticPcapng()
				r.pcapng.path = path
			} else {
				r.keylog.path = path
			}
			for offset := 0; offset < len(data); {
				end := min(offset+7, len(data))
				if err := r.handle(nativeEntry(format, data[offset:end])); err != nil {
					t.Fatal(err)
				}
				if err := r.handle(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_PROCESS_LOG, Payload: &pb.LogEntry_RunLog{RunLog: "runtime-marker"}}); err != nil {
					t.Fatal(err)
				}
				offset = end
			}
			if err := r.close(true); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("native bytes changed or logs entered artifact")
			}
			if !strings.Contains(console.String(), "runtime-marker") {
				t.Fatal("runtime logs disappeared")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("artifact permissions: %v %v", info, err)
			}
		})
	}
}

func TestReceiverRejectsModeChangeAndPreservesPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	r := &messageReceiver{output: io.Discard, keylog: artifactFile{path: path}}
	if err := r.handle(nativeEntry(pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, syntheticKeylog())); err != nil {
		t.Fatal(err)
	}
	if err := r.handle(nativeEntry(pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, syntheticPcapng())); err == nil {
		t.Fatal("mode switch accepted within one connection")
	}
	if err := r.close(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("incomplete artifact promoted")
	}
	if _, err := os.Stat(path + ".partial"); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverNormalCloseStillRejectsTruncatedArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	r := &messageReceiver{output: io.Discard, pcapng: artifactFile{path: path}}
	data := syntheticPcapng()
	if err := r.handle(nativeEntry(pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, data[:len(data)-2])); err != nil {
		t.Fatal(err)
	}
	if err := r.close(true); err == nil {
		t.Fatal("truncated pcapng promoted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("final artifact exists")
	}
}

func TestReceiverTextRetainsMetadataAndLabelsEveryLine(t *testing.T) {
	var console bytes.Buffer
	r := &messageReceiver{output: &console}
	text := &pb.TextEvent{Payload: []byte("one\ntwo\n"), Length: 8, Pid: 12, ProcessArgs: []byte{'a', 0, 0xff}, ProcessArgsTruncated: true, Tls: map[string]string{"alpn": "h2"}, StreamId: "s1", Sequence: 2}
	entry := &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT, Module: "gotls", Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_TEXT, Content: &pb.Event_Text{Text: text}}}}
	if err := r.handle(entry); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"process_args", "process_args_truncated", "alpn", "h2", "stream_id", "sequence", "one", "two"} {
		if !strings.Contains(console.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(console.String()), "\n") {
		if !strings.HasPrefix(line, "[log_type=event") {
			t.Fatalf("unlabelled line: %q", line)
		}
	}
}

func TestTerminalControlBytesCannotEraseRecordLabels(t *testing.T) {
	var output bytes.Buffer
	if err := writeLines(&output, "[log_type=event] ", "first\rreplace\x1b[2J\nsecond"); err != nil {
		t.Fatal(err)
	}
	want := "[log_type=event] first\\x0dreplace\\x1b[2J\n[log_type=event] second\n"
	if output.String() != want {
		t.Fatalf("terminal output=%q", output.String())
	}
}

func TestClientCloseStatusControlsArtifactCompletion(t *testing.T) {
	for _, code := range []int{websocket.CloseNormalClosure, websocket.CloseInternalServerErr, -1} {
		t.Run(fmt.Sprintf("close_%d", code), func(t *testing.T) {
			upgrader := websocket.Upgrader{Subprotocols: []string{protocol.Subprotocol}, CheckOrigin: func(request *http.Request) bool {
				return request.Header.Get("Origin") == "http://localhost/"
			}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				conn, err := upgrader.Upgrade(w, request, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				data, err := proto.Marshal(nativeEntry(pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, syntheticKeylog()))
				if err != nil {
					t.Error(err)
					return
				}
				if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
					t.Error(err)
					return
				}
				if code >= 0 {
					_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, "test"), time.Now().Add(time.Second))
				}
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "keys")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := runClient(ctx, options{server: "ws" + strings.TrimPrefix(server.URL, "http"), keylogFile: path}, io.Discard)
			if (err == nil) != (code == websocket.CloseNormalClosure) {
				t.Fatalf("close=%d err=%v", code, err)
			}
			_, finalErr := os.Stat(path)
			if (finalErr == nil) != (code == websocket.CloseNormalClosure) {
				t.Fatalf("incorrect artifact state for close %d", code)
			}
		})
	}
}

func TestClientRejectsMissingSubprotocol(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(w, request, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()
	if err := runClient(context.Background(), options{server: "ws" + strings.TrimPrefix(server.URL, "http")}, io.Discard); err == nil {
		t.Fatal("missing protocol negotiation accepted")
	}
}
