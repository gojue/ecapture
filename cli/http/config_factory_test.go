//go:build !ecap_android
// +build !ecap_android

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

package http

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	bashProbe "github.com/gojue/ecapture/v2/internal/probe/bash"
)

type httpConfigFactory func(*gin.Context) (*ConfigUpdate, error)

func factoryContext(body string) *gin.Context {
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	context.Request.Header.Set("Content-Type", "application/json")
	return context
}

func TestEveryHTTPConfigFactoryAppliesCommonConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := `{
		"pid":101,
		"uid":202,
		"debug":true,
		"is_hex":true,
		"btf_mode":2,
		"byte_code_file_mode":1,
		"per_cpu_map_size":65536,
		"truncate_size":303,
		"event_collector_addr":"/tmp/http-events.log",
		"event_rotate_size_mb":4,
		"event_rotate_seconds":5,
		"cgroup_path":"/sys/fs/cgroup/http",
		"perf_reorder":true,
		"perf_reorder_lag_ms":6
	}`
	want := config.CommonConfig{
		Pid:                101,
		Uid:                202,
		Debug:              true,
		Hex:                true,
		BTFMode:            2,
		ByteCodeFileMode:   1,
		PerCpuMapSize:      65536,
		TruncateSize:       303,
		EventCollectorAddr: "/tmp/http-events.log",
		EventRotateSizeMB:  4,
		EventRotateSeconds: 5,
		CGroupPath:         "/sys/fs/cgroup/http",
		PerfReorder:        true,
		PerfReorderLagMs:   6,
	}
	tests := []struct {
		name    string
		factory httpConfigFactory
	}{
		{name: "tls", factory: createOpensslConfig},
		{name: "gotls", factory: createGotlsConfig},
		{name: "gnutls", factory: createGnutlsConfig},
		{name: "bash", factory: createBashConfig},
		{name: "nspr", factory: createNsprConfig},
		{name: "mysqld", factory: createMysqlConfig},
		{name: "postgres", factory: createPostgresConfig},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			update, err := test.factory(factoryContext(body))
			if err != nil {
				t.Fatal(err)
			}
			got, err := config.CommonConfigFrom(update.Config)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("common config = %#v, want %#v", got, want)
			}
			if update.CommonPatch.EventCollectorAddr == nil ||
				update.CommonPatch.EventRotateSizeMB == nil ||
				update.CommonPatch.PerfReorder == nil {
				t.Fatal("factory discarded common field-presence metadata")
			}
		})
	}
}

func TestTLSHTTPConfigFactoriesPreserveTextSource(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name    string
		factory httpConfigFactory
	}{
		{"tls", createOpensslConfig},
		{"gotls", createGotlsConfig},
		{"gnutls", createGnutlsConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			update, err := test.factory(factoryContext(`{"text_source":"pcapng"}`))
			if err != nil {
				t.Fatal(err)
			}
			mode := update.Config.(domain.CaptureModeConfiguration)
			source := update.Config.(domain.TextSourceConfiguration)
			if mode.GetCaptureMode() != "text" || source.GetTextSource() != "pcapng" {
				t.Fatalf("mode/source = %q/%q, want text/pcapng", mode.GetCaptureMode(), source.GetTextSource())
			}
		})
	}
}

func TestHTTPReloadOutputMergeSemantics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	current := bashProbe.NewConfig()
	current.EventCollectorAddr = "/tmp/original-events.log"
	current.EventRotateSizeMB = 11
	current.EventRotateSeconds = 12

	tests := []struct {
		name        string
		body        string
		wantAddr    string
		wantSize    uint16
		wantSeconds uint16
		wantErr     bool
	}{
		{
			name:        "missing output fields inherit",
			body:        `{"pid":42}`,
			wantAddr:    current.EventCollectorAddr,
			wantSize:    current.EventRotateSizeMB,
			wantSeconds: current.EventRotateSeconds,
		},
		{
			name:        "explicit output fields replace",
			body:        `{"event_collector_addr":"/tmp/reloaded.log","event_rotate_size_mb":21,"event_rotate_seconds":22}`,
			wantAddr:    "/tmp/reloaded.log",
			wantSize:    21,
			wantSeconds: 22,
		},
		{
			name:        "explicit clear remains clear",
			body:        `{"event_collector_addr":"","event_rotate_size_mb":0,"event_rotate_seconds":0}`,
			wantAddr:    "",
			wantSize:    0,
			wantSeconds: 0,
		},
		{
			name:        "new network destination with inherited rotation is invalid",
			body:        `{"event_collector_addr":"tcp://127.0.0.1:28256"}`,
			wantAddr:    "tcp://127.0.0.1:28256",
			wantSize:    current.EventRotateSizeMB,
			wantSeconds: current.EventRotateSeconds,
			wantErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			update, err := createBashConfig(factoryContext(test.body))
			if err != nil {
				t.Fatal(err)
			}
			if err = config.MergeReloadOutput(current, update.Config, update.CommonPatch); err != nil {
				t.Fatal(err)
			}
			baseConfig, err := config.BaseConfigFor(update.Config)
			if err != nil {
				t.Fatal(err)
			}
			if baseConfig.EventCollectorAddr != test.wantAddr ||
				baseConfig.EventRotateSizeMB != test.wantSize ||
				baseConfig.EventRotateSeconds != test.wantSeconds {
				t.Fatalf("merged output = (%q, %d, %d), want (%q, %d, %d)",
					baseConfig.EventCollectorAddr,
					baseConfig.EventRotateSizeMB,
					baseConfig.EventRotateSeconds,
					test.wantAddr,
					test.wantSize,
					test.wantSeconds,
				)
			}
			err = baseConfig.ValidateTextOutput()
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateTextOutput() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestHTTPResponseWaitsForRuntimeDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	updates := make(chan *ConfigUpdate, 1)
	server := NewHttpServer("", updates, zerolog.Nop())

	tests := []struct {
		name       string
		result     error
		wantStatus int
	}{
		{name: "accepted", wantStatus: http.StatusOK},
		{name: "rejected", result: errors.New("candidate cannot start"), wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				update := <-updates
				update.Complete(test.result)
				close(done)
			}()

			request := httptest.NewRequest(http.MethodPost, "/bash", bytes.NewBufferString(`{"event_collector_addr":"/tmp/http-ack.log"}`))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			server.ge.ServeHTTP(recorder, request)
			<-done

			if recorder.Code != test.wantStatus {
				t.Fatalf("HTTP status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
}
