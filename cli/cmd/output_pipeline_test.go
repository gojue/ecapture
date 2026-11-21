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
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gojue/ecapture_decryptor/types"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/factory"
	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/output/decrypt"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
	"github.com/gojue/ecapture/v2/internal/probe/gotls"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
)

func TestCollectorInfoUsesBuildFactsAndValidatedGeneration(t *testing.T) {
	oldTime, oldCommit, oldConf := BuildTime, BuildCommit, globalConf
	t.Cleanup(func() { BuildTime, BuildCommit, globalConf = oldTime, oldCommit, oldConf })
	BuildTime, BuildCommit = "2026-11-21T08:00:00+08:00", "fixture-commit"
	globalConf.Outputs = []string{"stdout", "file:///tmp/synthetic.jsonl"}
	globalConf.StreamListen = "ws://127.0.0.1:28256/"
	argv := []string{"ecapture", "gotls", "--elfpath", "path with spaces"}
	info := newCollectorInfo(argv)
	argv[0], globalConf.Outputs[0] = "mutated", "stderr"
	if info.Argv[0] != "ecapture" || info.Argv[3] != "path with spaces" || info.Outputs[0] != "stdout" || info.ArgvTruncated {
		t.Fatalf("launch snapshot changed: %+v", info)
	}
	if info.BuildTime != "2026-11-21T00:00:00Z" || info.Commit != "fixture-commit" || info.Version != GitVersion {
		t.Fatalf("build facts missing: %+v", info)
	}
	cfg := gotls.NewConfig()
	cfg.CaptureMode, cfg.TextSource = "text", "pcapng"
	text := info.forCapture(cfg, "gotls")
	cfg.CaptureMode = "keylog"
	keylog := info.forCapture(cfg, "gotls")
	if text.Mode != "text" || text.TextSource != "pcapng" || keylog.Mode != "keylog" || keylog.TextSource != "" {
		t.Fatalf("generation facts stale: %+v / %+v", text, keylog)
	}
	BuildTime = ""
	if got := newCollectorInfo(nil).BuildTime; got != "" {
		t.Fatalf("unknown build time invented: %q", got)
	}
}

func TestCollectorInfoBoundsAndReplacementVersion(t *testing.T) {
	args, truncated := boundedInfoWords([]string{"ecapture", strings.Repeat("界", 8192), "last"}, 256, 8192)
	if !truncated || len(args) != 2 || !utf8.ValidString(args[1]) || len(args[0])+len(args[1]) > 8192 {
		t.Fatal("argv bound or UTF-8 boundary lost")
	}
	args, truncated = boundedInfoWords([]string{strings.Repeat("\xff", 8192)}, 256, 8192)
	encoded, err := json.Marshal(collectorInfo{Argv: args, ArgvTruncated: truncated})
	if err != nil || !truncated || !utf8.ValidString(args[0]) || len(encoded) > 256<<10 {
		t.Fatal("invalid argv did not remain bounded UTF-8")
	}
	args, truncated = boundedInfoWords([]string{"界", "x"}, 256, 2)
	if !truncated || len(args) != 1 || args[0] != "" {
		t.Fatal("argv after a truncated argument was retained")
	}
	for _, test := range []struct {
		replacement *debug.Module
		want        string
	}{
		{nil, "v1.2.3"},
		{&debug.Module{Path: "example.org/decryptor", Version: "v1.2.4"}, "example.org/decryptor@v1.2.4"},
		{&debug.Module{Path: "../local"}, "(local replacement)"},
	} {
		build := &debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/gojue/ecapture_decryptor", Version: "v1.2.3", Replace: test.replacement}}}
		if got := decryptorBuildVersion(build); got != test.want {
			t.Fatalf("version = %q, want %q", got, test.want)
		}
	}
}

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

func TestCombinedOutputPreservesLogAndEventClassification(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "records.jsonl")
	endpoints, err := parseOutputEndpoints([]string{outputPath})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := newOutputSet(endpoints, "tls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outputs.Close() })
	recorder := &typedOutputRecorder{}
	operational, err := newOperationalOutputs(false, outputs, recorder)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.NewBaseConfig()
	deps := &outputpipeline.RuntimeDependencies{
		OperationalLogger:   operational.logger,
		EventSinks:          []domain.CapturedEventSink{outputs, recorder},
		SuppressDefaultText: true,
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
	if err = outputs.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var fileEvents int
	var fileInitialized, fileClosed bool
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		entry := &pb.LogEntry{}
		if err := protojson.Unmarshal(line, entry); err != nil {
			t.Fatalf("invalid JSON Lines record: %v", err)
		}
		if entry.Module != "tls" {
			t.Fatalf("record module = %q", entry.Module)
		}
		switch entry.LogType {
		case pb.LogType_LOG_TYPE_PROCESS_LOG:
			message := []byte(entry.GetRunLog())
			if bytes.Contains(message, []byte(captured)) {
				t.Fatal("captured bytes mislabeled PROCESS_LOG")
			}
			fileInitialized = fileInitialized || bytes.Contains(message, []byte("Probe initialized"))
			fileClosed = fileClosed || bytes.Contains(message, []byte("Probe closed"))
		case pb.LogType_LOG_TYPE_EVENT:
			fileEvents++
			if string(entry.GetEventPayload().GetText().GetPayload()) != captured {
				t.Fatal("EVENT did not retain the captured text")
			}
		default:
			t.Fatalf("unexpected record kind %v", entry.LogType)
		}
	}
	if fileEvents != 1 || !fileInitialized || !fileClosed {
		t.Fatalf("combined file lost records: events=%d initialized=%v closed=%v", fileEvents, fileInitialized, fileClosed)
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

func TestNormalizeTLSOutputFlagsPreservesNativeDestinations(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		flag  string
		value string
	}{
		{name: "keylog file", mode: "keylog", flag: "keylogfile", value: "a.keys"},
		{name: "pcap file", mode: "pcapng", flag: "pcapfile", value: "a.pcapng"},
		{name: "pcap optional keylog", mode: "pcapng", flag: "keylogfile", value: "a.keys"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := &cobra.Command{Use: "test"}
			var keylogFile, pcapFile string
			command.Flags().StringVar(&keylogFile, "keylogfile", "", "")
			command.Flags().StringVar(&pcapFile, "pcapfile", "", "")
			if err := command.Flags().Set(test.flag, test.value); err != nil {
				t.Fatal(err)
			}
			source := handlers.TextSourceHook
			err := normalizeTLSOutputFlags(command, test.mode, &source, &keylogFile, &pcapFile)
			if err != nil {
				t.Fatal(err)
			}
			if test.flag == "keylogfile" && keylogFile != test.value || test.flag == "pcapfile" && pcapFile != test.value {
				t.Fatal("normalizing source changed an explicit native file")
			}
		})
	}
}

func TestNormalizeTLSPcapngTextOutputFlags(t *testing.T) {
	for _, savePcap := range []bool{false, true} {
		command := &cobra.Command{Use: "test"}
		var keylogFile, pcapFile string
		command.Flags().StringVar(&keylogFile, "keylogfile", "", "")
		command.Flags().StringVar(&pcapFile, "pcapfile", "", "")
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
	deps := p.Config().(*config.BaseConfig).RuntimeOutput
	if err := decrypt.Register(p.Context(), p.Fail, d, "lo", "", p.Logger(), "", "", nil, deps.EventSinks, true, types.DecryptOptions{}); err != nil {
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
		globalConf = CLIConfig{Outputs: []string{os.Getenv("ECAPTURE_TEST_LOG")}}
		cfg := config.NewBaseConfig()
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
	cmd.Env = append(os.Environ(), "ECAPTURE_PIPELINE_EXIT_TEST=1", "ECAPTURE_TEST_LOG="+logPath)
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
	if bytes.Count(logs, []byte("capture pipeline terminated")) != 1 {
		t.Fatalf("terminal cause must be reported once to the selected output: %s", logs)
	}
	if len(out) != 0 {
		t.Fatalf("file-only output unexpectedly wrote to the terminal: %s", out)
	}
}

type failedInitializationProbe struct {
	*base.BaseProbe
	ctx               context.Context
	path              string
	file              *os.File
	initErr, closeErr error
}

func (p *failedInitializationProbe) Initialize(ctx context.Context, _ domain.Configuration) error {
	p.ctx = ctx
	var err error
	p.file, err = os.Create(p.path)
	if err != nil {
		return err
	}
	return p.initErr
}
func (p *failedInitializationProbe) Close() error {
	return errors.Join(p.file.Close(), p.closeErr)
}

func TestFailedInitializationCancelsAndReleasesPartialResources(t *testing.T) {
	probe := &failedInitializationProbe{
		BaseProbe: base.NewBaseProbe("failed-init"), path: filepath.Join(t.TempDir(), "partial-artifact"),
		initErr: errors.New("probe initialization failed after resource allocation"), closeErr: errors.New("cleanup error"),
	}
	probeType := factory.ProbeType("failed-init-" + probe.path)
	if err := factory.RegisterProbe(probeType, func() (domain.Probe, error) { return probe, nil }); err != nil {
		t.Fatal(err)
	}
	logger := zerolog.New(io.Discard)
	generation, err := startProbeGeneration(context.Background(), probeType, config.NewBaseConfig(), &outputpipeline.RuntimeDependencies{}, &logger, false)
	if generation != nil || !errors.Is(err, probe.initErr) || !errors.Is(err, probe.closeErr) {
		t.Fatalf("initialization/cleanup result = %v", err)
	}
	if !errors.Is(probe.ctx.Err(), context.Canceled) {
		t.Fatal("failed generation context remained active")
	}
	if _, err := probe.file.Write([]byte("must be closed")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("partially initialized artifact was not closed: %v", err)
	}
}
