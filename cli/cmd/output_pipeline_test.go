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
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/gojue/ecapture_decryptor/types"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/factory"
	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/output/decrypt"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

func TestDecryptFlagsReachSDKOptions(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want types.DecryptOptions
	}{
		{"DNS", []string{"--text-protocol=dot"}, types.DecryptOptions{ApplicationProtocol: "dot"}},
		{"HTTP events", []string{"--text-http-events", "--text-max-decoded-body=4096"}, types.DecryptOptions{HTTPEvents: true, MaxDecodedBodyBytes: 4096}},
		{"STARTTLS raw", []string{"--text-tls-upgrade=smtp", "--text-raw"}, types.DecryptOptions{TLSUpgrade: "smtp", RawChunks: true}},
		{"DTLS", []string{"--text-udp-protocol=dtls"}, types.DecryptOptions{UDPProtocol: "dtls"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := &cobra.Command{Use: "capture"}
			var cfg config.DecryptConfig
			bindDecryptFlags(command, &cfg)
			if err := command.ParseFlags(test.args); err != nil {
				t.Fatal(err)
			}
			if err := cfg.ValidateDecryptOptions(true); err != nil {
				t.Fatal(err)
			}
			got := cfg.DecryptOptions()
			if got.RawChunks != test.want.RawChunks || got.ApplicationProtocol != test.want.ApplicationProtocol ||
				got.HTTPEvents != test.want.HTTPEvents || got.MaxDecodedBodyBytes != test.want.MaxDecodedBodyBytes ||
				got.TLSUpgrade != test.want.TLSUpgrade || got.UDPProtocol != test.want.UDPProtocol {
				t.Fatalf("SDK options = %#v, want %#v", got, test.want)
			}
		})
	}
}

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
			source := handlers.TextSourceHook
			err := normalizeTLSOutputFlags(command, test.mode, &source, &keylogFile, &pcapFile)
			if (err != nil) != test.wantErr {
				t.Fatalf("normalizeTLSOutputFlags() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestNormalizeTLSPcapngTextOutputFlags(t *testing.T) {
	for _, savePcap := range []bool{false, true} {
		command := &cobra.Command{Use: "test"}
		var eventAddress, keylogFile, pcapFile string
		command.Flags().StringVar(&eventAddress, "eventaddr", "", "")
		command.Flags().StringVar(&keylogFile, "keylogfile", "default.keys", "")
		command.Flags().StringVar(&pcapFile, "pcapfile", "default.pcapng", "")
		if savePcap {
			if err := command.Flags().Set("pcapfile", "capture.pcapng"); err != nil {
				t.Fatal(err)
			}
		}
		source := handlers.TextSourcePcapng
		if err := normalizeTLSOutputFlags(command, handlers.ModeText, &source, &keylogFile, &pcapFile); err != nil {
			t.Fatal(err)
		}
		if keylogFile != "" {
			t.Fatalf("default keylog artifact was enabled: %q", keylogFile)
		}
		wantPcap := ""
		if savePcap {
			wantPcap = "capture.pcapng"
		}
		if pcapFile != wantPcap {
			t.Fatalf("pcap artifact = %q, want %q", pcapFile, wantPcap)
		}
	}
}

// This probe uses real pcapng/decrypt handlers and the pinned SDK, but no BPF.
// Corrupt input causes a background SDK return with no dispatched event after it.
type failedPipelineProbe struct {
	*base.BaseProbe
	sink writers.ByteSink
}
type recordingDispatcher struct {
	domain.EventDispatcher
	sink *writers.ByteSink
}

func (d recordingDispatcher) Register(h domain.EventHandler) error {
	if h.Name() == handlers.ModePcapng {
		*d.sink = h.Writer()
	}
	return d.EventDispatcher.Register(h)
}
func (p *failedPipelineProbe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}
	d := recordingDispatcher{EventDispatcher: p.Dispatcher(), sink: &p.sink}
	if err := decrypt.Register(p.Context(), p.Fail, d, "lo", "", p.Logger(), p.Config().GetEventCollectorAddr(), "", nil, nil, types.DecryptOptions{}); err != nil {
		return err
	}
	reader, writer := io.Pipe()
	p.TrackReader(reader)
	p.GoReaderLoop(func() { _, _ = io.Copy(io.Discard, reader); _ = writer.Close() })
	go func() { _, _ = p.sink.Write(bytes.Repeat([]byte{0xff}, 64)) }()
	return nil
}

func TestPipelineFailureCLIExit(t *testing.T) {
	if os.Getenv("ECAPTURE_PIPELINE_EXIT_TEST") == "1" {
		const probeType factory.ProbeType = "pipeline-exit-test"
		if err := factory.RegisterProbe(probeType, func() (domain.Probe, error) {
			return &failedPipelineProbe{BaseProbe: base.NewBaseProbe("pipeline-test")}, nil
		}); err != nil {
			t.Fatal(err)
		}
		globalConf = CLIConfig{LoggerAddr: os.Getenv("ECAPTURE_TEST_LOG")}
		cfg := config.NewBaseConfig()
		cfg.SetEventCollectorAddr(os.Getenv("ECAPTURE_TEST_OUTPUT"))
		rootCmd.PersistentPreRunE = nil
		rootCmd.AddCommand(&cobra.Command{Use: "pipeline-exit-test", RunE: func(*cobra.Command, []string) error { return runProbe(probeType, cfg) }})
		rootCmd.SetArgs([]string{"pipeline-exit-test"})
		Execute()
		t.Fatal("Execute returned without a nonzero exit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	logPath := filepath.Join(t.TempDir(), "runtime.log")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPipelineFailureCLIExit$")
	cmd.Env = append(os.Environ(), "ECAPTURE_PIPELINE_EXIT_TEST=1", "ECAPTURE_TEST_LOG="+logPath, "ECAPTURE_TEST_OUTPUT="+filepath.Join(t.TempDir(), "plain"))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || ctx.Err() != nil {
		t.Fatalf("exit = %v, output=%s", err, out)
	}
	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(logs, []byte("Capture stopped after output pipeline failure")) != 1 || bytes.Contains(logs, []byte("Failed to dispatch")) || !bytes.Contains(logs, []byte("Probe closed")) {
		t.Fatalf("unexpected lifecycle logs: %s", logs)
	}
	if bytes.Count(out, []byte("capture pipeline terminated")) != 1 {
		t.Fatalf("terminal error repeated on console: %s", out)
	}
}
