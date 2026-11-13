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
	"time"

	decryptor "github.com/gojue/ecapture_decryptor"
	sdkcrypto "github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"

	"github.com/gojue/ecapture/v2/internal/domain"
	captureerrors "github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output/pcapng"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

// Register installs the low-latency packet handler and its borrowed DSB
// keylog adapter on one probe dispatcher.
func Register(ctx context.Context, fail func(error), dispatcher domain.EventDispatcher, ifName, filter string, logger *logger.Logger, eventAddr, pcapAddr string, rotation *writers.RotateConfig, eventSinks []domain.CapturedEventSink, options types.DecryptOptions) error {
	options.OnDiagnostic = diagnosticLogger(logger)
	sink, err := newSink(ctx, fail, eventAddr, pcapAddr, rotation, eventSinks, options, decryptor.DecryptPcapngStreamWithOptions)
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
	pipeReader *io.PipeReader
	plainSink  writers.ByteSink
	pcapSink   writers.ByteSink
	done       chan struct{}
	mu         sync.Mutex // lifecycle only; never held across I/O
	writeMu    sync.Mutex
	closed     bool
	finished   bool
	failure    error
	onFailure  func(error)
	cancel     context.CancelFunc
	stopWatch  func() bool
	closeOnce  sync.Once
	closeErr   error
	sequence   atomic.Uint64
}

const shutdownTimeout = 5 * time.Second

type streamDecrypt func(context.Context, io.ReadCloser, func(*types.DecryptedPacket) error, types.DecryptOptions) error

func NewSink(eventAddr, pcapAddr string, rotation *writers.RotateConfig, eventSinks []domain.CapturedEventSink, options types.DecryptOptions) (*Sink, error) {
	return newSink(context.Background(), nil, eventAddr, pcapAddr, rotation, eventSinks, options, decryptor.DecryptPcapngStreamWithOptions)
}

func newSink(parent context.Context, fail func(error), eventAddr, pcapAddr string, rotation *writers.RotateConfig, eventSinks []domain.CapturedEventSink, options types.DecryptOptions, run streamDecrypt) (*Sink, error) {
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
	ctx, cancel := context.WithCancel(context.Background())
	sink := &Sink{pipeWriter: pipeWriter, pipeReader: pipeReader, plainSink: plainSink, pcapSink: pcapSink, done: make(chan struct{}), cancel: cancel, onFailure: fail}
	// Cancellation allows final queued output to drain, then interrupts blocked I/O.
	sink.stopWatch = context.AfterFunc(parent, func() {
		timer := time.NewTimer(shutdownTimeout)
		defer timer.Stop()
		select {
		case <-sink.done:
		case <-timer.C:
			sink.Fail(context.DeadlineExceeded)
		}
	})
	go func() {
		err := run(ctx, pipeReader, func(packet *types.DecryptedPacket) (emitErr error) {
			defer func() {
				if emitErr != nil {
					sink.Fail(emitErr)
				}
			}()
			if err := sink.Err(); err != nil {
				return err
			}
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
				if err := publisher.PublishEvent(ctx, envelope); err != nil {
					return err
				}
			}
			return nil
		}, options)
		sink.mu.Lock()
		closing := sink.closed
		sink.mu.Unlock()
		// Only a locally initiated EOF is normal. A returned API is no longer
		// a usable pipeline, whatever connection errors its result contains.
		// An aggregate containing EOF can also contain a real failure.
		if !closing || (err != nil && err != io.EOF) { //nolint:errorlint // Only the exact expected EOF is normal.
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			sink.Fail(err)
		}
		_ = pipeReader.CloseWithError(sink.Err())
		close(sink.done)
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

// Fail latches one terminal cause and interrupts both ends without acquiring
// writeMu. It is also called by the pcapng session on encoder/flush failures.
func (s *Sink) Fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.failure != nil || s.finished {
		s.mu.Unlock()
		return
	}
	reason := "stream or output failed"
	// These are safe diagnostic labels only. Terminal state is established by
	// the caller, never inferred from a member of the SDK's aggregate error.
	switch {
	case errors.Is(err, sdkcrypto.ErrKeyLogResourceLimit):
		reason = "keylog import resource limit exceeded"
	case errors.Is(err, context.DeadlineExceeded):
		reason = "shutdown deadline exceeded"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		reason = "unexpected end of stream"
	}
	terminal := &captureerrors.PipelineError{Stage: "pcapng decryption", Reason: reason, Cause: err}
	s.failure = terminal
	s.mu.Unlock()
	s.cancel()
	_ = s.pipeReader.CloseWithError(terminal)
	_ = s.pipeWriter.CloseWithError(terminal)
	// Network sinks expose an interrupt that does not wait for a writer lock.
	for _, sink := range []writers.ByteSink{s.plainSink, s.pcapSink} {
		if abort, ok := sink.(interface{ Abort() }); ok {
			abort.Abort()
		}
	}
	if s.onFailure != nil {
		s.onFailure(terminal)
	}
}

func (s *Sink) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

func (s *Sink) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed, failure := s.closed, s.failure
	s.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if failure != nil {
		return 0, failure
	}
	if s.pcapSink != nil {
		n, err := s.pcapSink.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if err != nil {
			s.Fail(err)
			return 0, s.Err()
		}
	}
	n, err := s.pipeWriter.Write(p)
	if err != nil {
		s.mu.Lock()
		closed = s.closed
		s.mu.Unlock()
		if closed {
			return n, io.ErrClosedPipe
		}
		// The SDK may close its reader before returning the root error. Wait
		// for that result instead of replacing it with io.ErrClosedPipe.
		timer := time.NewTimer(shutdownTimeout)
		defer timer.Stop()
		select {
		case <-s.done:
		case <-timer.C:
			s.Fail(context.DeadlineExceeded)
		}
		if failure := s.Err(); failure != nil {
			return n, failure
		}
		return n, err
	}
	return n, nil
}

func (s *Sink) Flush() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.Err(); err != nil {
		return err
	}
	if s.pcapSink != nil {
		if err := s.pcapSink.Flush(); err != nil {
			s.Fail(err)
			return s.Err()
		}
	}
	return nil
}

func (s *Sink) Close() error {
	s.closeOnce.Do(func() {
		timer := time.AfterFunc(shutdownTimeout, func() { s.Fail(context.DeadlineExceeded) })
		defer timer.Stop()
		defer s.stopWatch()
		defer s.cancel()
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		// Do not wait behind a blocked pipe Write before closing its input.
		_ = s.pipeWriter.Close()
		<-s.done
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		var pcapErr error
		if s.pcapSink != nil {
			pcapErr = errors.Join(s.pcapSink.Flush(), s.pcapSink.Close())
		}
		outputErr := errors.Join(s.plainSink.Flush(), s.plainSink.Close(), pcapErr)
		s.mu.Lock()
		s.finished = true // late deadline callbacks must not turn success into failure
		failure := s.failure
		s.mu.Unlock()
		s.closeErr = captureerrors.JoinCleanup(failure, outputErr)
	})
	return s.closeErr
}

// One bucket per pipeline, not per connection or attacker-controlled reason.
// Never log SDK diagnostic text, connection identifiers, keys or payloads.
func diagnosticLogger(log *logger.Logger) func(types.Diagnostic) {
	var mu sync.Mutex
	var next time.Time
	var suppressed uint64
	return func(d types.Diagnostic) {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if now.Before(next) {
			if suppressed < ^uint64(0) {
				suppressed++
			}
			return
		}
		entry := log.Warn()
		switch d.Code {
		case "waiting_secret", "key_update", "key_update_requested", "hello_retry_request", "early_data_accepted", "early_data_rejected":
			entry = log.Debug()
		}
		// Codes come from the SDK, but cap and whitelist characters at this boundary.
		code := d.Code
		if len(code) > 64 {
			code = "other"
		}
		for _, c := range code {
			if c != '_' && (c < 'a' || c > 'z') {
				code = "other"
				break
			}
		}
		entry.Str("reason", code).Uint64("suppressed", suppressed).Msg("decrypt diagnostic")
		suppressed = 0
		next = now.Add(5 * time.Second)
	}
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
