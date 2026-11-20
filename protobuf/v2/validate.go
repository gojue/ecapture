// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package protocol defines the validation contract for eCapture's v2 messages.
package protocol

import (
	"fmt"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
)

// Subprotocol identifies the binary Protobuf v2 WebSocket protocol.
const Subprotocol = "ecapture.v2"

// ValidateLogEntry rejects mismatched discriminators and absent message bodies.
// Module names are intentionally open-ended; receivers must not guess a module
// from an unknown name or reject a new capture module's otherwise valid record.
func ValidateLogEntry(entry *pb.LogEntry) error {
	if entry == nil {
		return fmt.Errorf("nil log entry")
	}
	switch entry.LogType {
	case pb.LogType_LOG_TYPE_PROCESS_LOG:
		if value, ok := entry.Payload.(*pb.LogEntry_RunLog); !ok || value == nil {
			return fmt.Errorf("PROCESS_LOG requires run_log")
		}
	case pb.LogType_LOG_TYPE_HEARTBEAT:
		if value, ok := entry.Payload.(*pb.LogEntry_HeartbeatPayload); !ok || value == nil || value.HeartbeatPayload == nil {
			return fmt.Errorf("HEARTBEAT requires heartbeat_payload")
		}
	case pb.LogType_LOG_TYPE_EVENT:
		value, ok := entry.Payload.(*pb.LogEntry_EventPayload)
		if !ok || value == nil {
			return fmt.Errorf("EVENT requires event_payload")
		}
		return ValidateEvent(value.EventPayload)
	default:
		return fmt.Errorf("unknown log_type %d", entry.LogType)
	}
	return nil
}

// ValidateEvent enforces the capture_format/oneof contract. Empty text payloads
// remain valid for metadata-only events; raw stream fragments must carry bytes.
func ValidateEvent(event *pb.Event) error {
	if event == nil {
		return fmt.Errorf("EVENT requires event_payload")
	}
	switch event.CaptureFormat {
	case pb.CaptureFormat_CAPTURE_FORMAT_TEXT:
		value, ok := event.Content.(*pb.Event_Text)
		if !ok || value == nil || value.Text == nil {
			return fmt.Errorf("TEXT requires text content")
		}
		text := value.Text
		if uint64(text.Length) != uint64(len(text.Payload)) {
			return fmt.Errorf("TEXT length does not match payload")
		}
		if text.Sensitivity != pb.Sensitivity_SENSITIVITY_NORMAL && text.Sensitivity != pb.Sensitivity_SENSITIVITY_SENSITIVE {
			return fmt.Errorf("unknown text sensitivity %d", text.Sensitivity)
		}
	case pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG:
		if value, ok := event.Content.(*pb.Event_Keylog); !ok || value == nil || value.Keylog == nil || len(value.Keylog.Data) == 0 {
			return fmt.Errorf("KEYLOG requires non-empty keylog data")
		}
	case pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG:
		if value, ok := event.Content.(*pb.Event_Pcapng); !ok || value == nil || value.Pcapng == nil || len(value.Pcapng.Data) == 0 {
			return fmt.Errorf("PCAPNG requires non-empty pcapng data")
		}
	default:
		return fmt.Errorf("unknown capture_format %d", event.CaptureFormat)
	}
	return nil
}
