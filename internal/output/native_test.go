// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package output_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/output/pcapng"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

type nativeMemorySink struct {
	bytes.Buffer
	closeCalls int
	short      bool
}

func (s *nativeMemorySink) Name() string { return "native-memory" }
func (s *nativeMemorySink) Flush() error { return nil }
func (s *nativeMemorySink) Close() error { s.closeCalls++; return nil }
func (s *nativeMemorySink) Write(p []byte) (int, error) {
	if s.short {
		return s.Buffer.Write(p[:len(p)-1])
	}
	return s.Buffer.Write(p)
}

type nativeRecorder struct {
	events     []domain.CapturedEventEnvelope
	err        error
	closeCalls int
}

func (r *nativeRecorder) Name() string { return "native-recorder" }
func (r *nativeRecorder) Close() error { r.closeCalls++; return nil }
func (r *nativeRecorder) PublishEvent(_ context.Context, event domain.CapturedEventEnvelope) error {
	r.events = append(r.events, event)
	return r.err
}
func (r *nativeRecorder) data(t *testing.T, format domain.CaptureFormat) []byte {
	t.Helper()
	var data []byte
	for _, event := range r.events {
		if event.Format != format || event.Sensitivity != domain.SensitivitySensitive || event.DomainEvent != nil {
			t.Fatalf("invalid native event metadata: format=%s sensitivity=%s", event.Format, event.Sensitivity)
		}
		data = append(data, event.Payload...)
	}
	return data
}

type nativeSecret struct{}

func (*nativeSecret) GetLabel() string             { return "CLIENT_RANDOM" }
func (*nativeSecret) GetClientRandom() []byte      { return bytes.Repeat([]byte{1}, 32) }
func (*nativeSecret) GetSecret() []byte            { return bytes.Repeat([]byte{2}, 48) }
func (*nativeSecret) DecodeFromBytes([]byte) error { return nil }
func (*nativeSecret) Validate() error              { return nil }
func (*nativeSecret) String() string               { return "summary without secret" }
func (*nativeSecret) StringHex() string            { return "summary without secret" }
func (*nativeSecret) Clone() domain.Event          { return &nativeSecret{} }
func (*nativeSecret) Type() domain.EventType       { return domain.EventTypeOutput }
func (*nativeSecret) UUID() string                 { return "native-secret" }

func TestNativeKeylogPublishesNormalizedDeduplicatedRecords(t *testing.T) {
	raw, recorder := &nativeMemorySink{}, &nativeRecorder{}
	sink, err := output.NewNativeSink(raw, domain.CaptureFormatKeylog, []domain.CapturedEventSink{recorder})
	if err != nil {
		t.Fatal(err)
	}
	handler := handlers.NewKeylogHandler(writers.NewKeylogWriter(sink))
	for range 2 {
		if err := handler.Handle(&nativeSecret{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	want := []byte("CLIENT_RANDOM " + string(bytes.Repeat([]byte("01"), 32)) + " " + string(bytes.Repeat([]byte("02"), 48)) + "\n")
	if !bytes.Equal(raw.Bytes(), want) || !bytes.Equal(recorder.data(t, domain.CaptureFormatKeylog), want) {
		t.Fatal("typed keylog differs from normalized native records")
	}
	if len(recorder.events) != 1 || recorder.closeCalls != 0 || raw.closeCalls != 1 {
		t.Fatal("deduplication or borrowed publisher ownership changed")
	}
}

func TestNativePcapngPublishesHeadersPacketsAndSecrets(t *testing.T) {
	raw, recorder := &nativeMemorySink{}, &nativeRecorder{}
	sink, err := output.NewNativeSink(raw, domain.CaptureFormatPcapng, []domain.CapturedEventSink{recorder})
	if err != nil {
		t.Fatal(err)
	}
	session, err := pcapng.NewLowLatencySession(sink, 65535, "lo", "", logger.New(io.Discard, false))
	if err != nil {
		t.Fatal(err)
	}
	keylog := []byte("CLIENT_RANDOM " + string(bytes.Repeat([]byte("01"), 32)) + " " + string(bytes.Repeat([]byte("02"), 48)) + "\n")
	if err := session.WriteKeyLog(keylog); err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{7}, 60)
	if err := session.WritePacket(packet, time.Unix(1234, 0)); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	data := recorder.data(t, domain.CaptureFormatPcapng)
	if !bytes.Equal(raw.Bytes(), data) {
		t.Fatal("typed pcapng differs from native encoder bytes")
	}
	blocks := make(map[uint32]int)
	for remaining := data; len(remaining) != 0; {
		if len(remaining) < 12 {
			t.Fatal("short pcapng block")
		}
		length := int(binary.LittleEndian.Uint32(remaining[4:8]))
		if length < 12 || length > len(remaining) || length%4 != 0 {
			t.Fatal("invalid pcapng block size")
		}
		blocks[binary.LittleEndian.Uint32(remaining)]++
		remaining = remaining[length:]
	}
	for _, typ := range []uint32{0x0a0d0d0a, 1, 6, 10} {
		if blocks[typ] == 0 {
			t.Fatalf("missing pcapng block type %d", typ)
		}
	}
	if !bytes.Contains(data, keylog) {
		t.Fatal("encoded pcapng omitted DSB keylog data")
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := reader.ReadPacketData()
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("reconstructed packet mismatch: %v", err)
	}
}

func TestNativeSinkAttemptsAllDestinationsAndLatchesFailure(t *testing.T) {
	wantErr := errors.New("publisher failed")
	raw := &nativeMemorySink{short: true}
	failed, healthy := &nativeRecorder{err: wantErr}, &nativeRecorder{}
	sink, err := output.NewNativeSink(raw, domain.CaptureFormatKeylog, []domain.CapturedEventSink{failed, healthy})
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("record\n")
	if _, err := sink.Write(input); !errors.Is(err, io.ErrShortWrite) || !errors.Is(err, wantErr) {
		t.Fatalf("write error = %v", err)
	}
	input[0] = 'X'
	if !bytes.Equal(healthy.events[0].Payload, []byte("record\n")) {
		t.Fatal("publisher retained caller bytes")
	}
	if _, err := sink.Write([]byte("next\n")); !errors.Is(err, wantErr) {
		t.Fatal("failed stream resumed")
	}
	if len(failed.events) != 1 || len(healthy.events) != 1 {
		t.Fatal("fanout was skipped or retried after failure")
	}
	for range 2 {
		if err := sink.Close(); !errors.Is(err, wantErr) {
			t.Fatal("close lost stream error")
		}
	}
	if raw.closeCalls != 1 || healthy.closeCalls != 0 {
		t.Fatal("invalid close ownership")
	}
}

func TestNativeWorkerFailureNotifiesOwnerWithoutFurtherWrites(t *testing.T) {
	raw := &nativeMemorySink{}
	wantErr := errors.New("asynchronous encoder flush failed")
	var calls int
	var reported error
	sink, err := output.NewNativeSink(raw, domain.CaptureFormatPcapng, nil, func(err error) {
		calls++
		reported = err
	})
	if err != nil {
		t.Fatal(err)
	}
	sink.Fail(wantErr)
	sink.Fail(errors.New("subsequent encoder failure"))
	if calls != 1 || !errors.Is(reported, wantErr) || !errors.Is(sink.Err(), wantErr) {
		t.Fatalf("worker failure not preserved: calls=%d reported=%v latched=%v", calls, reported, sink.Err())
	}
	if _, err := sink.Write([]byte("must not resume")); !errors.Is(err, wantErr) || raw.Len() != 0 {
		t.Fatal("failed native pipeline resumed writes")
	}
	if err := sink.Close(); !errors.Is(err, wantErr) || raw.closeCalls != 1 {
		t.Fatal("cleanup lost the terminal failure or leaked the artifact")
	}
}

func TestNativePcapngReloadAppendsIndependentSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := os.WriteFile(path, []byte("stale data from a previous process"), 0600); err != nil {
		t.Fatal(err)
	}
	var packets [][]byte
	for generation := range 2 {
		raw, err := writers.NewWriterFactory().CreateEventSink(writers.EventSinkOptions{
			Address: path, Format: writers.EventFormatPcapng, Append: generation != 0,
		})
		if err != nil {
			t.Fatal(err)
		}
		session, err := pcapng.NewLowLatencySession(raw, 65535, "lo", "", logger.New(io.Discard, false))
		if err != nil {
			_ = raw.Close()
			t.Fatal(err)
		}
		packet := bytes.Repeat([]byte{byte(generation + 1)}, 60)
		packets = append(packets, packet)
		if err := session.WritePacket(packet, time.Unix(1234+int64(generation), 0)); err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(session.Close(), raw.Close()); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for generation, want := range packets {
		got, _, err := reader.ReadPacketData()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("generation %d packet lost after reload: %v", generation, err)
		}
	}
	if _, _, err := reader.ReadPacketData(); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected data after second generation: %v", err)
	}
}
