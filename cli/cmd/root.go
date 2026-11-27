// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/v2/cli/cobrautl"
	"github.com/gojue/ecapture/v2/cli/http"
	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	captureerrors "github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/factory"
	internalLogger "github.com/gojue/ecapture/v2/internal/logger"
	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/output/stream"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

const (
	CliName        = "eCapture"
	CliNameZh      = "旁观者"
	CliDescription = "Capture TLS plaintext with eBPF on Linux and Android"
	CliHomepage    = "https://ecapture.cc"
	CliAuthor      = "CFC4N <cfc4ncs@gmail.com>"
	CliGithubRepo  = "https://github.com/gojue/ecapture"
)

var (
	// GitVersion default value, eg: linux_arm64:v0.8.10-20241116-fcddaeb:5.15.0-125-generic
	GitVersion = "os_arch:v2.0.0-20260101-develop:default_kernel"
)

const (
	defaultPid          uint64 = 0
	defaultUid          uint64 = 0
	defaultTruncateSize uint64 = 0
)

// CLIConfig keeps serializable per-generation probe settings separate from
// process-lifetime output services owned by runProbe.
type CLIConfig struct {
	config.CommonConfig
	PerCpuMapPages int
	Outputs        []string
	ConfigListen   string
	StreamListen   string
}

var globalConf = CLIConfig{}
var rootCmd = &cobra.Command{
	Use:        "ecapture [command]",
	Short:      CliDescription,
	SuggestFor: []string{"ecapture"},

	Long: `eCapture (旁观者) decrypts captured TLS traffic without installing a CA certificate.
Choose tls for OpenSSL or BoringSSL, gotls for Go's crypto/tls, or gnutls for GnuTLS on Linux.
These commands display decoded application messages by default. They can also save TLS
session secrets or write a pcapng file for Wireshark.

Linux builds also capture NSPR data, shell commands, and SQL queries. Android builds
include the tls, gotls, and bash commands.

Minimum kernel versions are 4.18 on x86_64, 5.5 on aarch64, and 6.6 on loongarch64 (Linux only).

Project website: ` + CliHomepage + `
Source code: ` + CliGithubRepo,
	Example: `ecapture tls --model text --text-source pcapng
ecapture gotls --help
docker run --rm gojue/ecapture:latest tls --help`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Cobra runs this hook for "help <command>" but skips it for --help.
		if cmd.Name() == "help" {
			return nil
		}
		if _, err := parseOutputEndpoints(globalConf.Outputs); err != nil {
			return err
		}
		if globalConf.StreamListen != "" {
			if _, err := parseStreamAddress(globalConf.StreamListen); err != nil {
				return err
			}
		}
		if globalConf.ConfigListen != "" {
			if err := validateEndpointHost(globalConf.ConfigListen); err != nil {
				return err
			}
		}
		if err := detectEnv(); err != nil {
			return err
		}

		return nil
	},
}

func usageFunc(c *cobra.Command) error {
	return cobrautl.UsageFunc(c, GitVersion)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SetUsageFunc(usageFunc)
	rootCmd.SetHelpTemplate(`{{.UsageString}}`)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Version = GitVersion
	rootCmd.SetVersionTemplate(CliName + ` {{printf "version:\t%s" .Version}}
`)
	rootCmd.SilenceErrors = true
	err := rootCmd.Execute()
	if err != nil {
		if !captureerrors.IsPipelineError(err) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		os.Exit(1)
	}
}

func init() {
	cobra.EnablePrefixMatching = true
	if embeddedMode, err := config.EmbeddedByteCodeFileMode(); err == nil {
		globalConf.ByteCodeFileMode = embeddedMode
	}
	rootCmd.PersistentFlags().BoolVarP(&globalConf.Debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().Uint8VarP(&globalConf.BTFMode, "btf", "b", 0, "Select the eBPF bytecode `mode` (0 = automatic, 1 = require CO-RE, 2 = require non-CO-RE)")
	rootCmd.PersistentFlags().BoolVar(&globalConf.Hex, "hex", false, "Use hexadecimal formatting for hook-based text events that support it")
	rootCmd.PersistentFlags().IntVar(&globalConf.PerCpuMapPages, "mapsize", 1024, "Size of each CPU's perf event buffer in system `pages`")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Pid, "pid", "p", defaultPid, "Filter probe events by `PID` on kernel 5.2 or later (0 matches all processes)")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Uid, "uid", "u", defaultUid, "Filter probe events by `UID` on kernel 5.2 or later (0 matches all users)")
	rootCmd.PersistentFlags().StringArrayVar(&globalConf.Outputs, "output", nil, "Repeat for each `destination`. Use stdout (default) or stderr for text, or a file/FIFO path, file:///path, or tcp://host:port for JSON Lines. In keylog and pcapng modes, output files receive only runtime logs.")
	rootCmd.PersistentFlags().StringVar(&globalConf.ConfigListen, "config-listen", "", "Listen on `host:port` for HTTP configuration updates (disabled by default)")
	rootCmd.PersistentFlags().StringVar(&globalConf.StreamListen, "stream-listen", "", "Serve Protobuf v2 subscriptions at `ws://host:port/path` using the ecapture.v2 WebSocket subprotocol (disabled by default)")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.TruncateSize, "tsize", "t", defaultTruncateSize, "Text truncation limit in `bytes` (currently unused)")
	rootCmd.SilenceUsage = true
}

type operationalOutputs struct {
	logger *internalLogger.Logger
	sinks  []writers.ByteSink
}

func newOperationalOutputs(debug bool, publishers ...domain.OperationalLogSink) (*operationalOutputs, error) {
	destinations := make([]io.Writer, 0, len(publishers))
	for _, publisher := range publishers {
		adapter, err := outputpipeline.NewOperationalLogWriter(publisher)
		if err != nil {
			return nil, err
		}
		destinations = append(destinations, adapter)
	}
	level := zerolog.InfoLevel
	if debug {
		level = zerolog.DebugLevel
	}
	zlog := zerolog.New(zerolog.MultiLevelWriter(destinations...)).Level(level).With().Timestamp().Logger()
	return &operationalOutputs{logger: internalLogger.NewFromZerolog(zlog)}, nil
}

func (o *operationalOutputs) Close() error {
	if o == nil {
		return nil
	}
	var closeErrors []error
	for i := len(o.sinks) - 1; i >= 0; i-- {
		if err := o.sinks[i].Flush(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("flush %s: %w", o.sinks[i].Name(), err))
		}
		if err := o.sinks[i].Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close %s: %w", o.sinks[i].Name(), err))
		}
	}
	return errors.Join(closeErrors...)
}

func attachRuntimeOutputs(cfg domain.Configuration, deps *outputpipeline.RuntimeDependencies) error {
	provider, ok := cfg.(interface {
		SetRuntimeOutput(*outputpipeline.RuntimeDependencies)
	})
	if !ok {
		return fmt.Errorf("configuration %T cannot receive runtime output dependencies", cfg)
	}
	provider.SetRuntimeOutput(deps.Clone())
	return nil
}

var runConfiguredProbeFunc = runProbe

// runConfiguredProbe is the single Cobra-to-probe configuration boundary.
// Module-specific flags remain on their concrete config; all shared fields are
// applied here with their final runtime units.
func runConfiguredProbe(probeType factory.ProbeType, probeConfig domain.Configuration) error {
	common := globalConf.CommonConfig
	common.PerCpuMapSize = globalConf.PerCpuMapPages * os.Getpagesize()
	if err := config.ApplyCommonConfig(probeConfig, common); err != nil {
		return err
	}
	return runConfiguredProbeFunc(probeType, probeConfig)
}

// logTextSourceHint reminds TLS probes running in text mode that they can
// switch to the pcapng text source for more complete plaintext data.
func logTextSourceHint(logger *zerolog.Logger, probeConfig domain.Configuration) {
	modeConfig, ok := probeConfig.(domain.CaptureModeConfiguration)
	if !ok {
		return
	}
	textConfig, ok := probeConfig.(domain.TextSourceConfiguration)
	if !ok {
		return
	}
	if strings.EqualFold(modeConfig.GetCaptureMode(), handlers.ModeText) &&
		!strings.EqualFold(textConfig.GetTextSource(), handlers.TextSourcePcapng) {
		logger.Warn().Msg("text mode: for more complete data, use '--text-source pcapng' to decrypt directly from pcapng packets")
	}
}

type probeGeneration struct {
	probe         domain.Probe
	ctx           context.Context
	cancel        context.CancelFunc
	finishOutputs func(bool) error
	failed        bool
}

func startProbeGeneration(
	parent context.Context,
	probeType factory.ProbeType,
	probeConfig domain.Configuration,
	runtimeOutputs *outputpipeline.RuntimeDependencies,
	logger *zerolog.Logger,
	isReload bool,
) (*probeGeneration, error) {
	if err := attachRuntimeOutputs(probeConfig, runtimeOutputs); err != nil {
		return nil, err
	}
	if err := probeConfig.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	probeCtx, cancelProbe := context.WithCancel(parent)
	probe, err := factory.CreateProbe(probeType)
	if err != nil {
		cancelProbe()
		return nil, fmt.Errorf("failed to create probe: %w", err)
	}
	if err = probe.Initialize(probeCtx, probeConfig); err != nil {
		cancelProbe()
		return nil, errors.Join(fmt.Errorf("probe initialization failed: %w", err), probe.Close())
	}
	logger.Info().Str("probeName", string(probeType)).Bool("isReload", isReload).Msg("probe initialization.")
	if err = probe.Start(probeCtx); err != nil {
		cancelProbe()
		return nil, errors.Join(fmt.Errorf("probe start failed: %w", err), probe.Close())
	}
	logger.Info().Str("probeName", string(probeType)).Bool("isReload", isReload).Msg("probe started successfully.")
	return &probeGeneration{
		probe:  probe,
		ctx:    probeCtx,
		cancel: cancelProbe,
	}, nil
}

func (g *probeGeneration) done() <-chan struct{} {
	if p, ok := g.probe.(interface{ RuntimeDone() <-chan struct{} }); ok {
		return p.RuntimeDone()
	}
	return nil
}
func (g *probeGeneration) failure() error {
	if p, ok := g.probe.(interface{ RuntimeError() error }); ok {
		return p.RuntimeError()
	}
	return nil
}

func (g *probeGeneration) close() error {
	if g == nil {
		return nil
	}
	g.cancel()
	var shutdownErrors []error
	if err := g.probe.Stop(g.ctx); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("probe stop failed: %w", err))
	}
	if err := g.probe.Close(); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("probe close failed: %w", err))
	}
	if g.finishOutputs != nil {
		shutdownErrors = append(shutdownErrors, g.finishOutputs(!g.failed && g.failure() == nil && len(shutdownErrors) == 0))
	}
	if fatal := g.failure(); fatal != nil {
		return captureerrors.JoinCleanup(fatal, errors.Join(shutdownErrors...))
	}
	return errors.Join(shutdownErrors...)
}

func prepareReloadConfig(
	current domain.Configuration,
	update *http.ConfigUpdate,
	runtimeOutputs *outputpipeline.RuntimeDependencies,
) error {
	if update == nil || update.Config == nil {
		return fmt.Errorf("reload configuration cannot be nil")
	}
	if update.CommonPatch.EventCollectorAddr != nil || update.CommonPatch.EventRotateSizeMB != nil || update.CommonPatch.EventRotateSeconds != nil {
		return fmt.Errorf("output destinations are process-lifetime settings; removed event destination/rotation fields cannot be reloaded")
	}
	if fmt.Sprintf("%T", current) != fmt.Sprintf("%T", update.Config) {
		return fmt.Errorf("configuration updates must target the running probe type")
	}
	var err error
	if err = attachRuntimeOutputs(update.Config, runtimeOutputs); err != nil {
		return err
	}
	if err = update.Config.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	endpoints, err := parseOutputEndpoints(globalConf.Outputs)
	if err != nil {
		return err
	}
	return validateOutputArtifacts(update.Config, endpoints)
}

// runProbe runs a probe using the new internal/probe architecture
func runProbe(probeType factory.ProbeType, probeConfig domain.Configuration) (runErr error) {
	endpoints, err := parseOutputEndpoints(globalConf.Outputs)
	if err != nil {
		return err
	}
	runtimeOutputs := &outputpipeline.RuntimeDependencies{SuppressDefaultText: true, Module: moduleName(probeType)}
	if err = attachRuntimeOutputs(probeConfig, runtimeOutputs); err != nil {
		return err
	}
	if err = probeConfig.Validate(); err != nil {
		return err
	}
	if err = validateOutputArtifacts(probeConfig, endpoints); err != nil {
		return err
	}
	outputs, err := newOutputSet(endpoints, runtimeOutputs.Module)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, outputs.Close()) }()
	var streamServer *stream.Server
	publishers := []domain.OperationalLogSink{outputs}
	runtimeOutputs.EventSinks = []domain.CapturedEventSink{outputs}
	if globalConf.StreamListen != "" {
		address, parseErr := parseStreamAddress(globalConf.StreamListen)
		if parseErr != nil {
			return parseErr
		}
		streamServer = stream.NewServerWithPath(address.Host, address.Path, os.Stderr)
		publishers = append(publishers, streamServer)
		runtimeOutputs.EventSinks = append(runtimeOutputs.EventSinks, streamServer)
		runtimeOutputs.PcapngObservers = append(runtimeOutputs.PcapngObservers, streamServer)
	}
	operational, err := newOperationalOutputs(probeConfig.GetDebug(), publishers...)
	if err != nil {
		if streamServer != nil {
			_ = streamServer.Close()
		}
		return err
	}
	failureLogged := false
	logFailure := func(err error) {
		var terminal *captureerrors.PipelineError
		if !failureLogged && errors.As(err, &terminal) {
			failureLogged = true
			operational.logger.Error().Err(terminal).Msg("Capture stopped after output pipeline failure")
		}
	}
	defer func() {
		logFailure(runErr)
		runErr = errors.Join(runErr, operational.Close())
		if streamServer != nil {
			runErr = errors.Join(runErr, streamServer.Close())
		}
	}()
	logger := operational.logger.Logger

	var streamErrors <-chan error
	if streamServer != nil {
		streamErrors, err = streamServer.StartAsync()
		if err != nil {
			return err
		}
	}
	runtimeOutputs.OperationalLogger = operational.logger
	if err := attachRuntimeOutputs(probeConfig, runtimeOutputs); err != nil {
		return err
	}

	// init eCapture
	logger.Info().Str("AppName", fmt.Sprintf("%s(%s)", CliName, CliNameZh)).Send()
	logger.Info().Str("HomePage", CliHomepage).Send()
	logger.Info().Str("Repository", CliGithubRepo).Send()
	logger.Info().Str("Author", CliAuthor).Send()
	logger.Info().Str("Description", CliDescription).Send()
	logger.Info().Str("Version", GitVersion).Send()
	logger.Info().Strs("outputs", globalConf.Outputs).Str("config_listen", globalConf.ConfigListen).Str("stream_listen", globalConf.StreamListen).Msg("Output destinations configured (default stdout)")

	logTextSourceHint(logger, probeConfig)

	var reloadConfig = make(chan *http.ConfigUpdate, 10)
	var httpErrors <-chan error

	if globalConf.ConfigListen != "" {
		configServer := http.NewHttpServer(globalConf.ConfigListen, reloadConfig, *logger)
		httpErrors, err = configServer.StartAsync()
		if err != nil {
			return err
		}
		defer func() { runErr = errors.Join(runErr, configServer.Close()) }()
		logger.Info().Str("listen", globalConf.ConfigListen).Msg("HTTP configuration update service listening")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collector := newCollectorInfo(os.Args)

	// upgrade check
	go func() {
		// 1/10 概率触发
		if time.Now().UnixNano()%10 != 0 {
			return
		}
		tags, upgradeUrl, e := upgradeCheck(ctx)
		if e != nil {
			logger.Debug().Msgf("upgrade check failed: %s", e.Error())
			return
		}
		logger.Warn().Msgf("A new version %s is available:%s", tags, upgradeUrl)
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopper)

	startGeneration := func(cfg domain.Configuration, reload bool) (*probeGeneration, error) {
		if err := attachRuntimeOutputs(cfg, runtimeOutputs); err != nil {
			return nil, err
		}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		if err := validateOutputArtifacts(cfg, endpoints); err != nil {
			return nil, err
		}
		if err := outputs.BeginCapture(); err != nil {
			return nil, err
		}
		logger.Info().Str("event", "collector_info").Int("schemaVersion", 1).
			Interface("collector", collector.forCapture(cfg, runtimeOutputs.Module)).Msg("Collector runtime information")
		if streamServer != nil {
			format := domain.CaptureFormatText
			if mode, ok := cfg.(domain.CaptureModeConfiguration); ok {
				if handlers.IsModeKeylog(mode.GetCaptureMode()) {
					format = domain.CaptureFormatKeylog
				} else if !handlers.IsModeText(mode.GetCaptureMode()) {
					format = domain.CaptureFormatPcapng
				}
			}
			var fields map[string]any
			if jsonErr := json.Unmarshal(cfg.Bytes(), &fields); jsonErr != nil {
				return nil, errors.Join(jsonErr, outputs.EndCapture())
			}
			ifName, _ := fields["ifname"].(string)
			filter, _ := fields["pcapfilter"].(string)
			if filter == "" {
				filter, _ = fields["pcap_filter"].(string)
			}
			if err := streamServer.BeginCapture(format, runtimeOutputs.Module, ifName, filter, operational.logger); err != nil {
				return nil, errors.Join(err, outputs.EndCapture())
			}
		}
		finish := func(success bool) error {
			var streamErr error
			if streamServer != nil {
				if success {
					streamErr = streamServer.EndCapture()
				} else {
					streamErr = streamServer.AbortCapture()
				}
			}
			return errors.Join(streamErr, outputs.EndCapture())
		}
		generation, err := startProbeGeneration(ctx, probeType, cfg, runtimeOutputs, logger, reload)
		if err != nil {
			return nil, errors.Join(err, finish(false))
		}
		generation.finishOutputs = finish
		return generation, nil
	}
	active, err := startGeneration(probeConfig, false)
	if err != nil {
		return err
	}
	runtimeOutputs.AppendArtifacts = true
	for {
		select {
		case outputErr := <-outputs.failures:
			active.failed = true
			return errors.Join(outputErr, active.close())
		case <-active.done():
			logFailure(active.failure())
			return active.close()
		case _, ok := <-stopper:
			if !ok {
				logger.Warn().Msg("reload stopper channel closed.")
			}
			runErr = active.close()
			logger.Info().Msg("bye bye.")
			return runErr
		case update, ok := <-reloadConfig:
			if !ok {
				runErr = errors.Join(fmt.Errorf("reload config channel closed"), active.close())
				return runErr
			}
			if err = prepareReloadConfig(probeConfig, update, runtimeOutputs); err != nil {
				update.Complete(err)
				continue
			}

			logger.Warn().Msg("========== Reload accepted for switching; the probe will restart. ==========")
			previousConfig := probeConfig
			if err = active.close(); err != nil {
				update.Complete(err)
				return err
			}

			next, startErr := startGeneration(update.Config, true)
			if startErr != nil {
				reloadErr := fmt.Errorf("reload generation failed: %w", startErr)
				rollback, rollbackErr := startGeneration(previousConfig, true)
				if rollbackErr != nil {
					fatalErr := errors.Join(reloadErr, fmt.Errorf("restore previous generation failed: %w", rollbackErr))
					update.Complete(fatalErr)
					return fatalErr
				}
				active = rollback
				probeConfig = previousConfig
				update.Complete(reloadErr)
				logger.Error().Err(reloadErr).Msg("reload rejected; previous generation restored.")
				continue
			}

			active = next
			probeConfig = update.Config
			update.Complete(nil)
			logger.Info().RawJSON("config", probeConfig.Bytes()).Msg("probe reload completed.")
		case serverErr, ok := <-streamErrors:
			if !ok || serverErr == nil {
				err = fmt.Errorf("stream server stopped unexpectedly")
			} else {
				err = fmt.Errorf("stream server failed: %w", serverErr)
			}
			active.failed = true
			return errors.Join(err, active.close())
		case serverErr, ok := <-httpErrors:
			if !ok || serverErr == nil {
				err = fmt.Errorf("configuration HTTP server stopped unexpectedly")
			} else {
				err = fmt.Errorf("configuration HTTP server failed: %w", serverErr)
			}
			active.failed = true
			return errors.Join(err, active.close())
		}
	}
}
