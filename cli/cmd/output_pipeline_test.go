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

package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/probe/base"
)

type pipelineEvent struct{ payload []byte }

func (e *pipelineEvent) DecodeFromBytes([]byte) error { return nil }
func (e *pipelineEvent) String() string               { return string(e.payload) }
func (e *pipelineEvent) StringHex() string            { return string(e.payload) }
func (e *pipelineEvent) Clone() domain.Event {
	return &pipelineEvent{payload: append([]byte(nil), e.payload...)}
}
func (e *pipelineEvent) Type() domain.EventType { return domain.EventTypeOutput }
func (e *pipelineEvent) UUID() string           { return "pipeline-event" }
func (e *pipelineEvent) Validate() error        { return nil }
func (e *pipelineEvent) GetData() []byte        { return e.payload }
func (e *pipelineEvent) GetDataLen() uint32     { return uint32(len(e.payload)) }

type typedOutputRecorder struct {
	mu     sync.Mutex
	logs   []domain.OperationalLogRecord
	events []domain.CapturedEventEnvelope
}

func (r *typedOutputRecorder) PublishLog(_ context.Context, record domain.OperationalLogRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, record)
	return nil
}

func (r *typedOutputRecorder) PublishEvent(_ context.Context, event domain.CapturedEventEnvelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	event.Payload = append([]byte(nil), event.Payload...)
	r.events = append(r.events, event)
	return nil
}

func (r *typedOutputRecorder) Name() string { return "typed-recorder" }
func (r *typedOutputRecorder) Close() error { return nil }

func TestOperationalAndCapturedOutputsAreIsolated(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "runtime.log")
	eventPath := filepath.Join(directory, "events.log")
	recorder := &typedOutputRecorder{}
	operational, err := newOperationalOutputs(logPath, false, recorder)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.NewBaseConfig()
	cfg.SetEventCollectorAddr(eventPath)
	deps := &outputpipeline.RuntimeDependencies{
		OperationalLogger: operational.logger,
		EventSinks:        []domain.CapturedEventSink{recorder},
	}
	if err = attachRuntimeOutputs(cfg, deps); err != nil {
		t.Fatal(err)
	}
	probe := base.NewBaseProbe("output-isolation")
	if err = probe.Initialize(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err = probe.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	const captured = "captured-payload-must-not-be-a-process-log"
	if err = probe.Dispatcher().Dispatch(&pipelineEvent{payload: []byte(captured)}); err != nil {
		t.Fatal(err)
	}
	if err = probe.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}
	if err = operational.Close(); err != nil {
		t.Fatal(err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	eventData, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(logData, []byte(captured)) {
		t.Fatal("captured payload leaked into --logaddr output")
	}
	if !bytes.Contains(logData, []byte("Probe initialized")) || !bytes.Contains(logData, []byte("Probe closed")) {
		t.Fatalf("operational output lacks BaseProbe lifecycle: %s", logData)
	}
	if !bytes.Contains(eventData, []byte(captured)) {
		t.Fatalf("captured event output = %q", eventData)
	}
	if bytes.Contains(eventData, []byte("Probe initialized")) {
		t.Fatal("operational lifecycle leaked into event output")
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.events) != 1 || string(recorder.events[0].Payload) != captured {
		t.Fatalf("typed events = %#v", recorder.events)
	}
	var initialized, closed bool
	for _, record := range recorder.logs {
		initialized = initialized || bytes.Contains([]byte(record.Message), []byte("Probe initialized"))
		closed = closed || bytes.Contains([]byte(record.Message), []byte("Probe closed"))
		if bytes.Contains([]byte(record.Message), []byte(captured)) {
			t.Fatal("captured payload leaked into typed PROCESS_LOG")
		}
	}
	if !initialized || !closed {
		t.Fatalf("typed operational lifecycle missing: initialized=%v closed=%v", initialized, closed)
	}
}

func TestNormalizeTLSOutputFlagsConflicts(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		legacyFlag  string
		legacyValue string
		wantErr     bool
	}{
		{name: "keylog conflict", mode: "keylog", legacyFlag: "keylogfile", legacyValue: "a.keys", wantErr: true},
		{name: "pcap conflict", mode: "pcapng", legacyFlag: "pcapfile", legacyValue: "a.pcapng", wantErr: true},
		{name: "pcap optional keylog allowed", mode: "pcapng", legacyFlag: "keylogfile", legacyValue: "a.keys"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := &cobra.Command{Use: "test"}
			var eventAddress, keylogFile, pcapFile string
			command.Flags().StringVar(&eventAddress, "eventaddr", "", "")
			command.Flags().StringVar(&keylogFile, "keylogfile", "default.keys", "")
			command.Flags().StringVar(&pcapFile, "pcapfile", "default.pcapng", "")
			if err := command.Flags().Set("eventaddr", "tcp://127.0.0.1:9000"); err != nil {
				t.Fatal(err)
			}
			if err := command.Flags().Set(test.legacyFlag, test.legacyValue); err != nil {
				t.Fatal(err)
			}
			err := normalizeTLSOutputFlags(command, test.mode, &keylogFile, &pcapFile)
			if (err != nil) != test.wantErr {
				t.Fatalf("normalizeTLSOutputFlags() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
