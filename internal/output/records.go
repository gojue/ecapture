// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"maps"

	"github.com/gojue/ecapture/v2/internal/domain"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
)

func LogEntryForRecord(record domain.OperationalLogRecord) *pb.LogEntry {
	return &pb.LogEntry{Module: record.Module, LogType: pb.LogType_LOG_TYPE_PROCESS_LOG, Payload: &pb.LogEntry_RunLog{RunLog: record.Message}}
}

func LogEntryForEvent(event domain.CapturedEventEnvelope) *pb.LogEntry {
	value := &pb.Event{}
	switch event.Format {
	case domain.CaptureFormatText:
		sensitivity := pb.Sensitivity_SENSITIVITY_NORMAL
		if event.Sensitivity == domain.SensitivitySensitive {
			sensitivity = pb.Sensitivity_SENSITIVITY_SENSITIVE
		}
		value.CaptureFormat = pb.CaptureFormat_CAPTURE_FORMAT_TEXT
		value.Content = &pb.Event_Text{Text: &pb.TextEvent{
			Timestamp: event.Timestamp.Unix(), Uuid: event.UUID, SrcIp: event.SourceIP, SrcPort: event.SourcePort,
			DstIp: event.DestinationIP, DstPort: event.DestinationPort, Pid: int64(event.PID), Pname: event.ProcessName,
			Type: uint32(event.EventType), Length: uint32(len(event.Payload)), Payload: append([]byte(nil), event.Payload...),
			Sensitivity: sensitivity, Direction: event.Direction, OriginalLength: event.OriginalLength,
			StreamId: event.StreamID, Sequence: event.Sequence, ProcessArgs: append([]byte(nil), event.ProcessArgs...),
			ProcessArgsTruncated: event.ProcessArgsTruncated, Tls: maps.Clone(event.TLS),
		}}
	case domain.CaptureFormatKeylog:
		value.CaptureFormat = pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG
		value.Content = &pb.Event_Keylog{Keylog: &pb.KeylogEvent{Data: append([]byte(nil), event.Payload...)}}
	case domain.CaptureFormatPcapng:
		value.CaptureFormat = pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG
		value.Content = &pb.Event_Pcapng{Pcapng: &pb.PcapngEvent{Data: append([]byte(nil), event.Payload...)}}
	}
	return &pb.LogEntry{Module: event.Module, LogType: pb.LogType_LOG_TYPE_EVENT, Payload: &pb.LogEntry_EventPayload{EventPayload: value}}
}
