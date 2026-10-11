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
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gojue/ecapture/v2/internal/config"
	internalLogger "github.com/gojue/ecapture/v2/internal/logger"
	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/pkg/ecaptureq"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/v2/cli/cobrautl"
	"github.com/gojue/ecapture/v2/cli/http"
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/factory"
)

const (
	CliName        = "eCapture"
	CliNameZh      = "旁观者"
	CliDescription = "Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supports Linux amd64/arm64/loong64 and Android amd64/arm64."
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

// ListenPort1 or ListenPort2 are the default ports for the http server.
const (
	configUpdateAddr = ""
)

// CLIConfig keeps serializable per-generation probe settings separate from
// process-lifetime output services owned by runProbe.
type CLIConfig struct {
	config.CommonConfig
	PerCpuMapPages int
	LoggerAddr     string
	EcaptureQ      string
	Listen         string
}

var globalConf = CLIConfig{}
var rootCmd = &cobra.Command{
	Use:        CliName,
	Short:      CliDescription,
	SuggestFor: []string{"ecapture"},

	Long: `eCapture(旁观者) is a tool that can capture plaintext packets
such as HTTPS and TLS without installing a CA certificate.
It can also capture bash commands, which is suitable for
security auditing scenarios, such as database auditing of mysqld, etc (disabled on Android).
Support Linux x86_64 4.18+/aarch64 5.5+/LoongArch64 6.6+ and Android x86_64 4.18+/aarch64 5.5+.
Repository: https://github.com/gojue/ecapture
HomePage: https://ecapture.cc

Usage:
  ecapture tls -h
  ecapture bash -h

Docker usage:
docker pull gojue/ecapture:latest
docker run --rm --privileged=true --net=host -v ${HOST_PATH}:${CONTAINER_PATH} gojue/ecapture -h
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
	rootCmd.SetVersionTemplate(`{{with .Name}}{{printf "%s " .}}{{end}}{{printf "version:\t%s" .Version}}
`)
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.EnablePrefixMatching = true
	if embeddedMode, err := config.EmbeddedByteCodeFileMode(); err == nil {
		globalConf.ByteCodeFileMode = embeddedMode
	}
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().BoolVarP(&globalConf.Debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().Uint8VarP(&globalConf.BTFMode, "btf", "b", 0, "enable BTF mode.(0:auto; 1:core; 2:non-core)")
	rootCmd.PersistentFlags().BoolVar(&globalConf.Hex, "hex", false, "print byte strings as hex encoded strings")
	rootCmd.PersistentFlags().IntVar(&globalConf.PerCpuMapPages, "mapsize", 1024, "eBPF map size per CPU,for events buffer. default:1024 * PAGESIZE. (KB)")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Pid, "pid", "p", defaultPid, "if pid is 0 then we target all pids")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Uid, "uid", "u", defaultUid, "if uid is 0 then we target all users")
	rootCmd.PersistentFlags().StringVarP(&globalConf.LoggerAddr, "logaddr", "l", "", "send logs to this server. -l /tmp/ecapture.log or -l ws://127.0.0.1:8090/ecapture or -l tcp://127.0.0.1:8080")
	rootCmd.PersistentFlags().StringVar(&globalConf.EventCollectorAddr, "eventaddr", "", "captured-event destination: stdout, path, file://, tcp://, ws://, or wss:// (text defaults to stdout)")
	rootCmd.PersistentFlags().StringVar(&globalConf.EcaptureQ, "ecaptureq", "", "listening server, waiting for clients to connect before sending events and logs; false: send directly to the remote server.")
	rootCmd.PersistentFlags().StringVar(&globalConf.Listen, "listen", configUpdateAddr, "Listens on a port, receives HTTP requests, and is used to update the runtime configuration. default: disabled. e.g. --listen 127.0.0.1:28256")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.TruncateSize, "tsize", "t", defaultTruncateSize, "the truncate size in text mode, default: 0 (B), no truncate")
	rootCmd.PersistentFlags().Uint16Var(&globalConf.EventRotateSizeMB, "eventroratesize", 0, "the rorate size(MB) of the event collector file, 1M~65535M, only works for eventaddr server is file. --eventaddr=tls.log --eventroratesize=1 --eventroratetime=30")
	rootCmd.PersistentFlags().Uint16Var(&globalConf.EventRotateSeconds, "eventroratetime", 0, "the rorate time(s) of the event collector file, 1s~65535s, only works for eventaddr server is file. --eventaddr=tls.log --eventroratesize=1 --eventroratetime=30")
	rootCmd.SilenceUsage = true
}

type operationalOutputs struct {
	logger *internalLogger.Logger
	sinks  []writers.ByteSink
}

func newOperationalOutputs(addr string, debug bool, publisher domain.OperationalLogSink) (*operationalOutputs, error) {
	console := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	destinations := []io.Writer{console}
	result := &operationalOutputs{}
	if addr != "" {
		sink, err := writers.NewWriterFactory().CreateOperationalSink(addr, nil)
		if err != nil {
			return nil, fmt.Errorf("create operational log sink: %w", err)
		}
		result.sinks = append(result.sinks, sink)
		destinations = append(destinations, sink)
	}
	if publisher != nil {
		adapter, err := outputpipeline.NewOperationalLogWriter(publisher)
		if err != nil {
			_ = result.Close()
			return nil, err
		}
		destinations = append(destinations, adapter)
	}
	level := zerolog.InfoLevel
	if debug {
		level = zerolog.DebugLevel
	}
	zlog := zerolog.New(zerolog.MultiLevelWriter(destinations...)).
		Level(level).
		With().
		Timestamp().
		Logger()
	result.logger = internalLogger.NewFromZerolog(zlog)
	return result, nil
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
	baseConfig, err := config.BaseConfigFor(probeConfig)
	if err != nil {
		return err
	}
	// The operational logger itself is a borrowed RuntimeDependency. Its
	// address is retained only as immutable validation context (for example,
	// pcapng stdout channel separation).
	baseConfig.LoggerAddr = globalConf.LoggerAddr
	return runConfiguredProbeFunc(probeType, probeConfig)
}

type probeGeneration struct {
	probe  domain.Probe
	ctx    context.Context
	cancel context.CancelFunc
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
		return nil, fmt.Errorf("probe initialization failed: %w", err)
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
	if err := config.MergeReloadOutput(current, update.Config, update.CommonPatch); err != nil {
		return err
	}
	currentBase, err := config.BaseConfigFor(current)
	if err != nil {
		return err
	}
	candidateBase, err := config.BaseConfigFor(update.Config)
	if err != nil {
		return err
	}
	// Operational logging is a process-lifetime dependency. Keep its address as
	// immutable validation context even if a request body includes logger_addr.
	candidateBase.LoggerAddr = currentBase.LoggerAddr
	if err = attachRuntimeOutputs(update.Config, runtimeOutputs); err != nil {
		return err
	}
	if err = update.Config.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	return nil
}

// runProbe runs a probe using the new internal/probe architecture
func runProbe(probeType factory.ProbeType, probeConfig domain.Configuration) (runErr error) {
	var eqServer *ecaptureq.Server
	if globalConf.EcaptureQ != "" {
		listenAddr, err := ecaptureQListenAddress(globalConf.EcaptureQ)
		if err != nil {
			return err
		}
		eqServer = ecaptureq.NewServer(listenAddr, os.Stderr)
	}

	var operationalPublisher domain.OperationalLogSink
	if eqServer != nil {
		operationalPublisher = eqServer
	}
	operational, err := newOperationalOutputs(globalConf.LoggerAddr, probeConfig.GetDebug(), operationalPublisher)
	if err != nil {
		if eqServer != nil {
			_ = eqServer.Close()
		}
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, operational.Close())
		if eqServer != nil {
			runErr = errors.Join(runErr, eqServer.Close())
		}
	}()
	logger := operational.logger.Logger

	var eqErrors <-chan error
	if eqServer != nil {
		eqErrors, err = eqServer.StartAsync()
		if err != nil {
			return err
		}
	}
	runtimeOutputs := &outputpipeline.RuntimeDependencies{OperationalLogger: operational.logger}
	if eqServer != nil {
		runtimeOutputs.EventSinks = append(runtimeOutputs.EventSinks, eqServer)
	}
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
	logger.Info().Str("Listen", globalConf.Listen).Send()
	logger.Info().Str("Listen for eCaptureQ", globalConf.EcaptureQ).Send()
	logger.Info().Str("logger", globalConf.LoggerAddr).Msg("eCapture running logs")
	logger.Info().Str("eventCollector", probeConfig.GetEventCollectorAddr()).Msg("the file handler that receives the captured event")

	var reloadConfig = make(chan *http.ConfigUpdate, 10)
	var httpErrors <-chan error

	// listen http server
	if globalConf.Listen != "" {
		serverErrors := make(chan error, 1)
		httpErrors = serverErrors
		go func() {
			logger.Info().Str("listen", globalConf.Listen).Send()
			logger.Info().Msg("https server starting...You can upgrade the configuration file via the HTTP interface.")
			var ec = http.NewHttpServer(globalConf.Listen, reloadConfig, *logger)
			serverErrors <- ec.Run()
			close(serverErrors)
		}()
	} else {
		logger.Info().Msg("skip HTTP server listening")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	active, err := startProbeGeneration(ctx, probeType, probeConfig, runtimeOutputs, logger, false)
	if err != nil {
		return err
	}
	for {
		select {
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

			next, startErr := startProbeGeneration(ctx, probeType, update.Config, runtimeOutputs, logger, true)
			if startErr != nil {
				reloadErr := fmt.Errorf("reload generation failed: %w", startErr)
				rollback, rollbackErr := startProbeGeneration(ctx, probeType, previousConfig, runtimeOutputs, logger, true)
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
		case serverErr, ok := <-eqErrors:
			if !ok || serverErr == nil {
				err = fmt.Errorf("ecaptureq server stopped unexpectedly")
			} else {
				err = fmt.Errorf("ecaptureq server failed: %w", serverErr)
			}
			return errors.Join(err, active.close())
		case serverErr, ok := <-httpErrors:
			if !ok || serverErr == nil {
				err = fmt.Errorf("configuration HTTP server stopped unexpectedly")
			} else {
				err = fmt.Errorf("configuration HTTP server failed: %w", serverErr)
			}
			return errors.Join(err, active.close())
		}
	}
}

func ecaptureQListenAddress(value string) (string, error) {
	parsedURL, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid ecaptureq address: %w", err)
	}
	if parsedURL.Scheme != "ws" {
		return "", fmt.Errorf("ecaptureq address must use ws://")
	}
	if parsedURL.Host == "" {
		return "", fmt.Errorf("ecaptureq address requires a host and port")
	}
	return parsedURL.Host, nil
}
