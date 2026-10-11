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

package cmd

import (
	"os"
	"strings"
	"testing"

	confighttp "github.com/gojue/ecapture/v2/cli/http"
	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/factory"
	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
	bashProbe "github.com/gojue/ecapture/v2/internal/probe/bash"
	gnutlsProbe "github.com/gojue/ecapture/v2/internal/probe/gnutls"
	gotlsProbe "github.com/gojue/ecapture/v2/internal/probe/gotls"
	mysqlProbe "github.com/gojue/ecapture/v2/internal/probe/mysql"
	nsprProbe "github.com/gojue/ecapture/v2/internal/probe/nspr"
	opensslProbe "github.com/gojue/ecapture/v2/internal/probe/openssl"
	postgresProbe "github.com/gojue/ecapture/v2/internal/probe/postgres"
	zshProbe "github.com/gojue/ecapture/v2/internal/probe/zsh"
)

type commonTextConfig struct {
	*config.BaseConfig
}

func (c *commonTextConfig) Validate() error {
	return c.BaseConfig.ValidateTextOutput()
}

func TestEveryCobraCommandAppliesCommonConfig(t *testing.T) {
	originalGlobal := globalConf
	originalRunner := runConfiguredProbeFunc
	defer func() {
		globalConf = originalGlobal
		runConfiguredProbeFunc = originalRunner
	}()

	globalConf = CLIConfig{
		CommonConfig: config.CommonConfig{
			Pid:                101,
			Uid:                202,
			Debug:              true,
			Hex:                true,
			BTFMode:            config.BTFModeNonCore,
			ByteCodeFileMode:   config.ByteCodeFileNonCore,
			TruncateSize:       303,
			EventCollectorAddr: "/tmp/cli-common-events.log",
			EventRotateSizeMB:  4,
			EventRotateSeconds: 5,
			CGroupPath:         "/sys/fs/cgroup/cli-common",
			PerfReorder:        true,
			PerfReorderLagMs:   6,
		},
		PerCpuMapPages: 7,
		LoggerAddr:     "/tmp/cli-operational.log",
	}

	var capturedType factory.ProbeType
	var capturedConfig domain.Configuration
	runConfiguredProbeFunc = func(probeType factory.ProbeType, probeConfig domain.Configuration) error {
		capturedType = probeType
		capturedConfig = probeConfig
		return nil
	}

	tests := []struct {
		name      string
		probeType factory.ProbeType
		run       func() error
	}{
		{
			name:      "tls",
			probeType: factory.ProbeTypeOpenSSL,
			run: func() error {
				opensslConfig = opensslProbe.NewConfig()
				return openSSLCommandFunc(opensslCmd, nil)
			},
		},
		{
			name:      "gotls",
			probeType: factory.ProbeTypeGoTLS,
			run: func() error {
				gotlsConfig = gotlsProbe.NewConfig()
				return goTLSCommandFunc(gotlsCmd, nil)
			},
		},
		{
			name:      "gnutls",
			probeType: factory.ProbeTypeGnuTLS,
			run: func() error {
				gnutlsConfig = gnutlsProbe.NewConfig()
				return gnuTlsCommandFunc(gnutlsCmd, nil)
			},
		},
		{
			name:      "bash",
			probeType: factory.ProbeTypeBash,
			run: func() error {
				bashConfig = bashProbe.NewConfig()
				return bashCommandFunc(bashCmd, nil)
			},
		},
		{
			name:      "zsh",
			probeType: factory.ProbeTypeZsh,
			run: func() error {
				zshConfig = zshProbe.NewConfig()
				return zshCommandFunc(zshCmd, nil)
			},
		},
		{
			name:      "mysqld",
			probeType: factory.ProbeTypeMySQL,
			run: func() error {
				mysqlConfig = mysqlProbe.NewConfig()
				return mysqldCommandFunc(mysqldCmd, nil)
			},
		},
		{
			name:      "postgres",
			probeType: factory.ProbeTypePostgres,
			run: func() error {
				postgresConfig = postgresProbe.NewConfig()
				return postgresCommandFunc(postgresCmd, nil)
			},
		},
		{
			name:      "nspr",
			probeType: factory.ProbeTypeNSPR,
			run: func() error {
				nsprConfig = nsprProbe.NewConfig()
				return nssCommandFunc(nssCmd, nil)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capturedType = ""
			capturedConfig = nil
			if err := test.run(); err != nil {
				t.Fatal(err)
			}
			if capturedType != test.probeType {
				t.Fatalf("probe type = %q, want %q", capturedType, test.probeType)
			}
			if capturedConfig == nil {
				t.Fatal("command did not invoke the common probe runner")
			}
			common, err := config.CommonConfigFrom(capturedConfig)
			if err != nil {
				t.Fatal(err)
			}
			want := globalConf.CommonConfig
			want.PerCpuMapSize = globalConf.PerCpuMapPages * os.Getpagesize()
			if common != want {
				t.Fatalf("common config = %#v, want %#v", common, want)
			}
			baseConfig, err := config.BaseConfigFor(capturedConfig)
			if err != nil {
				t.Fatal(err)
			}
			if baseConfig.LoggerAddr != globalConf.LoggerAddr {
				t.Fatalf("logger validation context = %q, want %q", baseConfig.LoggerAddr, globalConf.LoggerAddr)
			}
		})
	}
}

func TestEveryTextProbeRejectsUnsupportedEventDestination(t *testing.T) {
	tests := []struct {
		name   string
		config domain.Configuration
	}{
		{name: "bash", config: bashProbe.NewConfig()},
		{name: "zsh", config: zshProbe.NewConfig()},
		{name: "mysqld", config: mysqlProbe.NewConfig()},
		{name: "postgres", config: postgresProbe.NewConfig()},
		{name: "nspr", config: nsprProbe.NewConfig()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseConfig, err := config.BaseConfigFor(test.config)
			if err != nil {
				t.Fatal(err)
			}
			baseConfig.EventCollectorAddr = "udp://127.0.0.1:9"
			err = test.config.Validate()
			if err == nil {
				t.Fatal("unsupported event destination was accepted")
			}
			if !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("validation error %q does not explain the unsupported destination", err)
			}
		})
	}
}

func TestPrepareReloadConfigInheritsOutputAndReattachesRuntime(t *testing.T) {
	current := &commonTextConfig{BaseConfig: config.NewBaseConfig()}
	current.EventCollectorAddr = "/tmp/current-events.log"
	current.EventRotateSizeMB = 8
	current.EventRotateSeconds = 9
	current.LoggerAddr = "/tmp/current-operational.log"

	candidate := &commonTextConfig{BaseConfig: config.NewBaseConfig()}
	patch, err := config.DecodeCommonConfigPatch([]byte(`{"pid":42}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = patch.Apply(candidate); err != nil {
		t.Fatal(err)
	}
	candidate.LoggerAddr = "/tmp/request-must-not-replace-operational.log"
	runtimeOutputs := &outputpipeline.RuntimeDependencies{}
	update := &confighttp.ConfigUpdate{Config: candidate, CommonPatch: patch}

	for i := 0; i < 2; i++ {
		if err = prepareReloadConfig(current, update, runtimeOutputs); err != nil {
			t.Fatal(err)
		}
	}
	if candidate.EventCollectorAddr != current.EventCollectorAddr ||
		candidate.EventRotateSizeMB != current.EventRotateSizeMB ||
		candidate.EventRotateSeconds != current.EventRotateSeconds {
		t.Fatalf("candidate output was not inherited: %#v", candidate.BaseConfig)
	}
	if candidate.LoggerAddr != current.LoggerAddr {
		t.Fatalf("candidate logger context = %q, want %q", candidate.LoggerAddr, current.LoggerAddr)
	}
	if candidate.RuntimeOutput == nil || candidate.RuntimeOutput == runtimeOutputs {
		t.Fatal("runtime output dependencies were not reattached as a clone")
	}
}

func TestPrepareReloadConfigRejectsInvalidDestinationWithoutMutatingCurrent(t *testing.T) {
	current := &commonTextConfig{BaseConfig: config.NewBaseConfig()}
	current.EventCollectorAddr = "/tmp/still-active.log"
	candidate := &commonTextConfig{BaseConfig: config.NewBaseConfig()}
	patch, err := config.DecodeCommonConfigPatch([]byte(`{
		"event_collector_addr":"udp://127.0.0.1:9",
		"event_rotate_size_mb":0,
		"event_rotate_seconds":0
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = patch.Apply(candidate); err != nil {
		t.Fatal(err)
	}
	update := &confighttp.ConfigUpdate{Config: candidate, CommonPatch: patch}
	if err = prepareReloadConfig(current, update, &outputpipeline.RuntimeDependencies{}); err == nil {
		t.Fatal("invalid destination was accepted")
	}
	if current.EventCollectorAddr != "/tmp/still-active.log" {
		t.Fatalf("active config mutated after rejected update: %q", current.EventCollectorAddr)
	}
}
