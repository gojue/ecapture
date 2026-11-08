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

// Package decrypt connects an in-process pcapng writer to the independent
// ecapture_decryptor SDK and routes application messages or raw chunks to a ByteSink.
package decrypt

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync"
	"sync/atomic"

	decryptor "github.com/gojue/ecapture_decryptor"
	"github.com/gojue/ecapture_decryptor/types"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output/pcapng"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

// Register installs the low-latency packet handler and its borrowed DSB
// keylog adapter on one probe dispatcher.
func Register(dispatcher domain.EventDispatcher, ifName, filter string, logger *logger.Logger, eventAddr, pcapAddr string, rotation *writers.RotateConfig, eventSinks []domain.CapturedEventSink, options types.DecryptOptions) error {
	options.OnDiagnostic = func(d types.Diagnostic) {
		entry := logger.Warn()
		switch d.Code {
		case "waiting_secret", "key_update", "key_update_requested", "hello_retry_request",
			"early_data_accepted", "early_data_rejected":
			entry = logger.Debug()
		}
		entry.Str("connection", d.ConnectionID).Str("transport", d.Transport).
			Str("stage", d.Stage).Str("reason", d.Code).Msg("decrypt diagnostic")
	}
	sink, err := NewSink(eventAddr, pcapAddr, rotation, eventSinks, options)
	if err != nil {
		return err
	}
	packetHandler, err := handlers.NewLowLatencyPcapngHandler(sink, ifName, filter, logger)
	if err != nil {
		_ = sink.Close()
		return err
	}
	if err := dispatcher.Register(packetHandler); err != nil {
		_ = packetHandler.Close()
		return err
	}
	keylogHandler := handlers.NewKeylogHandler(pcapng.NewKeylogAdapter(packetHandler.Session()))
	if err := dispatcher.Register(keylogHandler); err != nil {
		_ = dispatcher.Unregister(packetHandler.Name() + "-" + sink.Name())
		_ = packetHandler.Close()
		return err
	}
	return nil
}

// Sink is the pcapng input for the reconstructed text source. It can save a copy of
// the original pcapng bytes when requested. Only the SDK callback writes the
// plaintext sink, so message output preserves SDK delivery order.
type Sink struct {
	pipeWriter *io.PipeWriter
	plainSink  writers.ByteSink
	pcapSink   writers.ByteSink
	done       chan error
	mu         sync.Mutex
	closed     bool
	closeOnce  sync.Once
	closeErr   error
	sequence   atomic.Uint64
}

func NewSink(eventAddr, pcapAddr string, rotation *writers.RotateConfig, eventSinks []domain.CapturedEventSink, options types.DecryptOptions) (*Sink, error) {
	if err := options.Validate(); err != nil {
		return nil, fmt.Errorf("invalid decrypt options: %w", err)
	}
	factory := writers.NewWriterFactory()
	plainSink, err := factory.CreateEventSink(writers.EventSinkOptions{
		Address: eventAddr, Format: writers.EventFormatText, RotateConfig: rotation, Sensitive: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create decrypted event sink: %w", err)
	}
	var pcapSink writers.ByteSink
	if pcapAddr != "" {
		pcapSink, err = factory.CreateEventSink(writers.EventSinkOptions{
			Address: pcapAddr, Format: writers.EventFormatPcapng,
		})
		if err != nil {
			_ = plainSink.Close()
			return nil, fmt.Errorf("create optional pcapng sink: %w", err)
		}
	}
	pipeReader, pipeWriter := io.Pipe()
	sink := &Sink{pipeWriter: pipeWriter, plainSink: plainSink, pcapSink: pcapSink, done: make(chan error, 1)}
	go func() {
		err := decryptor.DecryptPcapngStreamWithOptions(context.Background(), pipeReader, func(packet *types.DecryptedPacket) error {
			payload, err := formatMessage(packet)
			if err != nil {
				return err
			}
			if n, err := plainSink.Write(payload); err != nil {
				return err
			} else if n != len(payload) {
				return io.ErrShortWrite
			}
			if err := plainSink.Flush(); err != nil {
				return err
			}
			sequence := sink.sequence.Add(1)
			for _, publisher := range eventSinks {
				envelope := messageEnvelope(packet, payload, sequence)
				if err := publisher.PublishEvent(context.Background(), envelope); err != nil {
					return err
				}
			}
			return nil
		}, options)
		_ = pipeReader.CloseWithError(err)
		sink.done <- err
	}()
	return sink, nil
}

func messageEnvelope(packet *types.DecryptedPacket, formatted []byte, sequence uint64) domain.CapturedEventEnvelope {
	envelope := domain.CapturedEventEnvelope{
		Timestamp: packet.Timestamp, UUID: packet.ConnectionID(), EventType: domain.EventTypeOutput,
		Format: domain.CaptureFormatText, Sensitivity: domain.SensitivitySensitive,
		SourceIP: packet.SrcIP, SourcePort: packet.SrcPort,
		DestinationIP: packet.DstIP, DestinationPort: packet.DstPort,
		ProcessName: packet.PName, Direction: packet.Direction,
		Payload: append([]byte(nil), packet.Data...), OriginalLength: uint32(len(packet.Data)), Sequence: sequence,
	}
	if packet.PID > 0 {
		envelope.PID = uint64(packet.PID)
		if packet.ProcessArgs != nil {
			envelope.ProcessArgs = append([]byte(nil), packet.ProcessArgs.Data...)
			envelope.ProcessArgsTruncated = packet.ProcessArgs.Truncated
		}
	}
	if tls, ok := packet.Metadata["tls"].(map[string]string); ok {
		envelope.TLS = maps.Clone(tls)
	}
	// Structured events can carry metadata without payload. Preserve both using
	// the existing text representation and existing protobuf process fields.
	if structuredMessage(packet) {
		envelope.Payload = append([]byte(nil), formatted...)
		envelope.OriginalLength = uint32(len(formatted))
	}
	if id, ok := packet.Metadata["stream_id"]; ok {
		envelope.StreamID = fmt.Sprint(id)
	}
	return envelope
}

func (s *Sink) Name() string { return "decrypt-pcapng-stream" }

func (s *Sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if s.pcapSink != nil {
		if _, err := s.pcapSink.Write(p); err != nil {
			return 0, err
		}
	}
	return s.pipeWriter.Write(p)
}

func (s *Sink) Flush() error {
	if s.pcapSink != nil {
		return s.pcapSink.Flush()
	}
	return nil
}

func (s *Sink) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		pipeErr := s.pipeWriter.Close()
		s.mu.Unlock()
		decryptErr := <-s.done
		var pcapErr error
		if s.pcapSink != nil {
			pcapErr = errors.Join(s.pcapSink.Flush(), s.pcapSink.Close())
		}
		s.closeErr = errors.Join(pipeErr, decryptErr, s.plainSink.Flush(), s.plainSink.Close(), pcapErr)
	})
	return s.closeErr
}

func structuredMessage(packet *types.DecryptedPacket) bool {
	_, kind := packet.Metadata["kind"]
	_, depth := packet.Metadata["tls_depth"]
	return kind || depth
}

func formatMessage(packet *types.DecryptedPacket) ([]byte, error) {
	var out bytes.Buffer
	if structuredMessage(packet) {
		metadata, err := json.Marshal(packet.Metadata)
		if err != nil {
			return nil, fmt.Errorf("encode decrypted event metadata: %w", err)
		}
		kind, ok := packet.Metadata["kind"]
		if !ok {
			kind = "message"
		}
		direction := "client_to_server"
		if packet.Direction == "response" {
			direction = "server_to_client"
		}
		fmt.Fprintf(&out, "[%s] %s %s %s:%d -> %s:%d connection=%q kind=%v",
			packet.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00"), packet.Protocol,
			direction, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort,
			packet.ConnectionID(), kind)
		if offset, ok := packet.Metadata["offset"]; ok {
			fmt.Fprintf(&out, " offset=%v", offset)
		}
		if end, ok := packet.Metadata["end"]; ok {
			fmt.Fprintf(&out, " end=%v", end)
		}
		fmt.Fprintf(&out, " length=%d encoding=hex", len(packet.Data))
		if streamID, ok := packet.Metadata["stream_id"]; ok {
			fmt.Fprintf(&out, " stream=%v", streamID)
		}
		fmt.Fprintf(&out, " metadata=%s\n%s\n\n", metadata, hex.EncodeToString(packet.Data))
		return out.Bytes(), nil
	}
	host, _ := packet.Metadata["host"].(string)
	source := "Host"
	if host == "" {
		host, _ = packet.Metadata["authority"].(string)
		source = ":authority"
	}
	if host == "" {
		host = packet.DstIP
		if packet.Direction == "response" {
			host = packet.SrcIP
		}
		source = "server_ip"
	}
	fmt.Fprintf(&out, "[%s] %s %s %s:%d -> %s:%d host=%q domain_source=%q connection=%q",
		packet.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00"), packet.Protocol,
		packet.Direction, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort,
		host, source, packet.ConnectionID())
	if streamID, ok := packet.Metadata["stream_id"]; ok {
		fmt.Fprintf(&out, " stream=%v", streamID)
	}
	out.WriteByte('\n')
	out.Write(packet.Data)
	if len(packet.Data) == 0 || packet.Data[len(packet.Data)-1] != '\n' {
		out.WriteByte('\n')
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
