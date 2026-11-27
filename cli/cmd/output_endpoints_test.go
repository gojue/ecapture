// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gojue/ecapture/v2/internal/domain"
	openssl "github.com/gojue/ecapture/v2/internal/probe/openssl"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
)

func TestOutputDestinationsAndRemovedFlags(t *testing.T) {
	defaults, err := parseOutputEndpoints(nil)
	if err != nil || len(defaults) != 1 || defaults[0].kind != "stdout" {
		t.Fatalf("default = %#v, %v", defaults, err)
	}
	for _, values := range [][]string{{""}, {"console"}, {"-"}, {"stdout", "stdout"}, {"tcp://host"}, {"ws://host:9"}, {"wss://host:9"}, {"tcp://host:0"}, {"tcp://host:9/path"}, {"file://remote/tmp/file"}, {"listen+ws://localhost:9"}, {"tcp://user:pass@host:9"}, {"/dev/null"}} {
		if _, err := parseOutputEndpoints(values); err == nil {
			t.Errorf("accepted invalid destinations: %q", values)
		}
	}
	path := filepath.Join(t.TempDir(), "records,with-comma.jsonl")
	values, err := parseOutputEndpoints([]string{"stdout", "stderr", path, "tcp://127.0.0.1:9999"})
	if err != nil || len(values) != 4 || values[2].address != path {
		t.Fatalf("array destination parse: %v", err)
	}
	for _, name := range []string{"eventaddr", "logaddr", "ecaptureq", "listen", "eventroratesize", "eventroratetime"} {
		if rootCmd.PersistentFlags().Lookup(name) != nil {
			t.Errorf("removed flag %s still registered", name)
		}
	}
	if rootCmd.PersistentFlags().ShorthandLookup("l") != nil {
		t.Error("removed -l still registered")
	}
	flag := rootCmd.PersistentFlags().Lookup("output")
	if flag == nil || flag.Value.Type() != "stringArray" {
		t.Fatal("output must be a repeatable string array, preserving commas in filenames")
	}
	for _, value := range []string{"127.0.0.1:9", "wss://127.0.0.1:9", "ws://127.0.0.1:9/path?query=1"} {
		if _, err := parseStreamAddress(value); err == nil {
			t.Errorf("accepted invalid listener: %s", value)
		}
	}
}

func TestOutputRejectsArtifactAndAliasCollisions(t *testing.T) {
	dir := t.TempDir()
	path, link := filepath.Join(dir, "capture"), filepath.Join(dir, "alias")
	if err := os.WriteFile(path, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := parseOutputEndpoints([]string{path, link}); err == nil {
		t.Fatal("duplicate hard-linked outputs accepted")
	}
	cfg := openssl.NewConfig()
	cfg.PcapFile = path
	endpoints, err := parseOutputEndpoints([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOutputArtifacts(cfg, endpoints); err == nil {
		t.Fatal("JSON and native artifact alias accepted")
	}
	cfg.KeylogFile = link
	if err := validateOutputArtifacts(cfg, nil); err == nil {
		t.Fatal("keylog and pcapng alias accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "retain" {
		t.Fatal("validation opened or truncated an artifact")
	}
}

func TestOutputRejectsEscapedArtifactAliases(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"capture.pcapng", "capture%2Epcapng"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("retain"), 0600); err != nil {
				t.Fatal(err)
			}
			address := (&url.URL{Scheme: "file", Path: path}).String()
			endpoints, err := parseOutputEndpoints([]string{address})
			if err != nil {
				t.Fatal(err)
			}
			cfg := openssl.NewConfig()
			for _, artifact := range []string{path, address} {
				cfg.PcapFile = artifact
				if err := validateOutputArtifacts(cfg, endpoints); err == nil {
					t.Fatalf("accepted output/native alias %q", artifact)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "retain" {
				t.Fatal("validation changed the existing file")
			}
		})
	}
}

func TestOutputFileURIPreservesLiteralPercent(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"100%.jsonl", "capture%2Ejsonl"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			address := (&url.URL{Scheme: "file", Path: path}).String()
			endpoints, err := parseOutputEndpoints([]string{address})
			if err != nil {
				t.Fatal(err)
			}
			outputs, err := newOutputSet(endpoints, "tls")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = outputs.Close() })
			if err := outputs.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "ready"}); err != nil {
				t.Fatal(err)
			}
			if err := outputs.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			entry := &pb.LogEntry{}
			if err := protojson.Unmarshal(data, entry); err != nil {
				t.Fatal(err)
			}
			if entry.GetRunLog() != "ready" || entry.GetModule() != "tls" {
				t.Fatalf("unexpected output record: %v", entry)
			}
		})
	}
}

func TestOutputModeRoutingAndGenerationBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	endpoints, err := parseOutputEndpoints([]string{path, "tcp://" + listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := newOutputSet(endpoints, "tls")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outputs.Close() }()
	readGeneration := func(format domain.CaptureFormat) {
		t.Helper()
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := outputs.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "ready"}); err != nil {
			t.Fatal(err)
		}
		if err := outputs.PublishEvent(context.Background(), domain.CapturedEventEnvelope{Format: format, Payload: []byte("encoded")}); err != nil {
			t.Fatal(err)
		}
		if err := outputs.EndCapture(); err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			entry := &pb.LogEntry{}
			if err := protojson.Unmarshal(scanner.Bytes(), entry); err != nil {
				t.Fatal(err)
			}
			if entry.Module != "tls" {
				t.Fatal("module omitted")
			}
			count++
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Fatalf("network records = %d", count)
		}
	}
	for i, format := range []domain.CaptureFormat{domain.CaptureFormatText, domain.CaptureFormatPcapng, domain.CaptureFormatKeylog} {
		if i > 0 {
			if err := outputs.BeginCapture(); err != nil {
				t.Fatal(err)
			}
		}
		readGeneration(format)
	}
	if err := outputs.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	logs, events := 0, 0
	for scanner.Scan() {
		entry := &pb.LogEntry{}
		if err := protojson.Unmarshal(scanner.Bytes(), entry); err != nil {
			t.Fatal(err)
		}
		if entry.LogType == pb.LogType_LOG_TYPE_PROCESS_LOG {
			logs++
		} else {
			events++
			if entry.GetEventPayload().GetText() == nil {
				t.Fatal("native event leaked to JSON file")
			}
		}
	}
	if logs != 3 || events != 1 {
		t.Fatalf("file logs/events = %d/%d", logs, events)
	}
	if err := outputs.BeginCapture(); err == nil {
		t.Fatal("closed outputs reopened")
	}
}

type failingLifecyclePublisher struct {
	typedOutputRecorder
	publishErr error
	closeErr   error
	closes     int
}

func (p *failingLifecyclePublisher) PublishLog(ctx context.Context, record domain.OperationalLogRecord) error {
	_ = p.typedOutputRecorder.PublishLog(ctx, record)
	return p.publishErr
}
func (p *failingLifecyclePublisher) Close() error { p.closes++; return p.closeErr }

func TestOutputClosePreservesFinalLogFailureAfterNotification(t *testing.T) {
	publishErr, closeErr := errors.New("terminal write failed"), errors.New("destination close failed")
	failed := &failingLifecyclePublisher{publishErr: publishErr, closeErr: closeErr}
	healthy := &failingLifecyclePublisher{}
	outputs := &outputSet{
		module: "tls", failures: make(chan error, 1),
		targets: []outputTarget{
			{endpoint: outputEndpoint{kind: "stdout"}, publisher: failed},
			{endpoint: outputEndpoint{kind: "file"}, publisher: healthy},
		},
	}
	if err := outputs.PublishLog(context.Background(), domain.OperationalLogRecord{Message: "final lifecycle record"}); !errors.Is(err, publishErr) {
		t.Fatalf("publish failure = %v", err)
	}
	if len(healthy.logs) != 1 {
		t.Fatal("one failed endpoint prevented delivery to another endpoint")
	}
	select {
	case <-outputs.failures:
	default:
		t.Fatal("owner was not notified of output failure")
	}
	for range 2 {
		if err := outputs.Close(); !errors.Is(err, publishErr) || !errors.Is(err, closeErr) {
			t.Fatalf("cleanup lost final output failure after notification was consumed: %v", err)
		}
	}
	if failed.closes != 1 || healthy.closes != 1 {
		t.Fatal("output ownership did not close every endpoint exactly once")
	}
}

func TestOutputFIFOValidationAndAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	alias := path + ".alias"
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	endpoints, err := parseOutputEndpoints([]string{"file://" + path})
	if err != nil || len(endpoints) != 1 || endpoints[0].kind != "file" {
		t.Fatalf("FIFO endpoint = %v, %v", endpoints, err)
	}
	if _, err := parseOutputEndpoints([]string{path, alias}); err == nil {
		t.Fatal("duplicate FIFO accepted")
	}
	cfg := openssl.NewConfig()
	cfg.KeylogFile = alias
	if err := validateOutputArtifacts(cfg, endpoints); err == nil {
		t.Fatal("JSON/native FIFO alias accepted")
	}
	cfg.PcapFile = path
	if err := validateOutputArtifacts(cfg, nil); err == nil {
		t.Fatal("keylog/pcapng FIFO alias accepted")
	}
}
