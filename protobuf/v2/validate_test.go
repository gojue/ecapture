// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	v1 "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
)

func TestValidateLogEntryDiscriminators(t *testing.T) {
	tests := []struct {
		name  string
		entry *pb.LogEntry
		valid bool
	}{
		{name: "nil"},
		{name: "missing heartbeat", entry: &pb.LogEntry{}},
		{name: "heartbeat", entry: &pb.LogEntry{Payload: &pb.LogEntry_HeartbeatPayload{HeartbeatPayload: &pb.Heartbeat{}}}, valid: true},
		{name: "empty log", entry: &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_PROCESS_LOG, Payload: &pb.LogEntry_RunLog{}}, valid: true},
		{name: "log with event body", entry: &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_PROCESS_LOG, Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{}}}},
		{name: "event missing body", entry: &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT}},
		{name: "unknown log type", entry: &pb.LogEntry{LogType: pb.LogType(99), Payload: &pb.LogEntry_RunLog{RunLog: "test"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateLogEntry(test.entry); (err == nil) != test.valid {
				t.Fatalf("ValidateLogEntry() = %v, valid = %v", err, test.valid)
			}
		})
	}
}

func TestValidateEventFormats(t *testing.T) {
	tests := []struct {
		name  string
		event *pb.Event
		valid bool
	}{
		{name: "nil"},
		{name: "unspecified", event: &pb.Event{}},
		{name: "metadata only text", event: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_TEXT, Content: &pb.Event_Text{Text: &pb.TextEvent{StreamId: "stream"}}}, valid: true},
		{name: "text wrong length", event: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_TEXT, Content: &pb.Event_Text{Text: &pb.TextEvent{Length: 1}}}},
		{name: "text wrong sensitivity", event: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_TEXT, Content: &pb.Event_Text{Text: &pb.TextEvent{Sensitivity: pb.Sensitivity(44)}}}},
		{name: "keylog fragment", event: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, Content: &pb.Event_Keylog{Keylog: &pb.KeylogEvent{Data: []byte("CLIENT_")}}}, valid: true},
		{name: "pcapng fragment", event: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, Content: &pb.Event_Pcapng{Pcapng: &pb.PcapngEvent{Data: []byte{0x0a, 0x0d}}}}, valid: true},
		{name: "empty keylog", event: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, Content: &pb.Event_Keylog{Keylog: &pb.KeylogEvent{}}}},
		{name: "mismatched native format", event: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, Content: &pb.Event_Keylog{Keylog: &pb.KeylogEvent{Data: []byte("key")}}}},
		{name: "unknown format", event: &pb.Event{CaptureFormat: pb.CaptureFormat(81), Content: &pb.Event_Text{Text: &pb.TextEvent{}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateEvent(test.event); (err == nil) != test.valid {
				t.Fatalf("ValidateEvent() = %v, valid = %v", err, test.valid)
			}
		})
	}
}

func TestV2BinaryAndJSONPreserveTextMetadata(t *testing.T) {
	text := &pb.TextEvent{
		Timestamp: 123, Uuid: "id", Pid: 42, Pname: "client", Type: 7,
		SrcIp: "127.0.0.1", SrcPort: 1234, DstIp: "127.0.0.2", DstPort: 443,
		Payload: []byte{0xff, 0, 'a'}, Length: 3, OriginalLength: 9,
		Sensitivity: pb.Sensitivity_SENSITIVITY_SENSITIVE, Direction: "read",
		ProcessArgs: []byte{'x', 0, 0xfe}, ProcessArgsTruncated: true,
		StreamId: "h2-1", Sequence: 1 << 54, Tls: map[string]string{"alpn": "h2"},
	}
	entry := &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT, Module: "tls", Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_TEXT, Content: &pb.Event_Text{Text: text}}}}
	if err := ValidateLogEntry(entry); err != nil {
		t.Fatal(err)
	}
	for _, jsonEncoding := range []bool{false, true} {
		var data []byte
		var err error
		if jsonEncoding {
			data, err = (protojson.MarshalOptions{UseProtoNames: true}).Marshal(entry)
		} else {
			data, err = proto.Marshal(entry)
		}
		if err != nil {
			t.Fatal(err)
		}
		var decoded pb.LogEntry
		if jsonEncoding {
			err = protojson.Unmarshal(data, &decoded)
		} else {
			err = proto.Unmarshal(data, &decoded)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(entry, &decoded) {
			t.Fatalf("round trip changed metadata (JSON=%v)", jsonEncoding)
		}
	}
	// Both schemas may remain imported by source packages without descriptor collisions.
	if v1.File_v1_ecaptureq_proto.Package() == pb.File_v2_ecaptureq_proto.Package() {
		t.Fatal("v1 and v2 share a protobuf namespace")
	}
}

func TestV2NativeBytesJSONEncoding(t *testing.T) {
	entry := &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT, Module: "gotls", Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{CaptureFormat: pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, Content: &pb.Event_Pcapng{Pcapng: &pb.PcapngEvent{Data: []byte{0xff, 0, 1}}}}}}
	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`/wAB`)) {
		t.Fatalf("native bytes were not encoded once as base64: %s", data)
	}
	var decoded pb.LogEntry
	if err = protojson.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.GetEventPayload().GetPcapng().GetData(), []byte{0xff, 0, 1}) {
		t.Fatal("native bytes changed")
	}
}
