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
	"fmt"
	"github.com/gojue/ecapture/cli/cobrautl"
	"github.com/gojue/ecapture/cli/http"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/module"
	"github.com/rs/zerolog"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const (
	CliName        = "eCapture"
	CliNameZh      = "旁观者"
	CliDescription = "Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supported on Linux/Android kernels for amd64/arm64."
	CliHomepage    = "https://ecapture.cc"
	CliAuthor      = "CFC4N <cfc4ncs@gmail.com>"
	CliRepo        = "https://github.com/gojue/ecapture"
)

var (
	GitVersion = "v0.0.0_unknow"
	//ReleaseDate = "2022-03-16"
)

const (
	defaultPid uint64 = 0
	defaultUid uint64 = 0
)

const (
	loggerTypeStdout = 0
	loggerTypeFile   = 1
	loggerTypeTcp    = 2
)

// ListenPort1 or ListenPort2 are the default ports for the http server.
const (
	eCaptureListenAddr = "localhost:28256"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:        CliName,
	Short:      CliDescription,
	SuggestFor: []string{"ecapture"},

	Long: `eCapture(旁观者) is a tool that can capture plaintext packets 
such as HTTPS and TLS without installing a CA certificate.
It can also capture bash commands, which is suitable for 
security auditing scenarios, such as database auditing of mysqld, etc (disabled on Android).
Support Linux(Android)  X86_64 4.18/aarch64 5.5 or newer.
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

var globalConf = config.BaseConfig{}

func init() {
	cobra.EnablePrefixMatching = true
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().BoolVarP(&globalConf.Debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().Uint8VarP(&globalConf.BtfMode, "btf", "b", 0, "enable BTF mode.(0:auto; 1:core; 2:non-core)")
	rootCmd.PersistentFlags().BoolVar(&globalConf.IsHex, "hex", false, "print byte strings as hex encoded strings")
	rootCmd.PersistentFlags().IntVar(&globalConf.PerCpuMapSize, "mapsize", 1024, "eBPF map size per CPU,for events buffer. default:1024 * PAGESIZE. (KB)")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Pid, "pid", "p", defaultPid, "if pid is 0 then we target all pids")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Uid, "uid", "u", defaultUid, "if uid is 0 then we target all users")
	rootCmd.PersistentFlags().StringVarP(&globalConf.LoggerAddr, "logaddr", "l", "", "send logs to this server. -l /tmp/ecapture.log or -l tcp://127.0.0.1:8080")
	rootCmd.PersistentFlags().StringVar(&globalConf.EventCollectorAddr, "eventaddr", "", "the server address that receives the captured event. --eventaddr tcp://127.0.0.1:8090, default: same as logaddr")
	rootCmd.PersistentFlags().StringVar(&globalConf.Listen, "listen", eCaptureListenAddr, "listen on this address for http server, default: 127.0.0.1:28256")
}

// eventCollector
type eventCollectorWriter struct {
	logger *zerolog.Logger
}

func (e eventCollectorWriter) Write(p []byte) (n int, err error) {
	return e.logger.Write(p)
}

// setModConfig set module config
func setModConfig(globalConf config.BaseConfig, modConf config.IConfig) {
	modConf.SetPid(globalConf.Pid)
	modConf.SetUid(globalConf.Uid)
	modConf.SetDebug(globalConf.Debug)
	modConf.SetHex(globalConf.IsHex)
	modConf.SetBTF(globalConf.BtfMode)
	modConf.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	modConf.SetAddrType(loggerTypeStdout)
}

// initLogger init logger
func initLogger(addr string, modConfig config.IConfig) zerolog.Logger {
	var logger zerolog.Logger
	var err error
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if modConfig.GetDebug() {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if addr != "" {
		var writer io.Writer
		var address string
		if strings.Contains(addr, "tcp://") {
			address = strings.Replace(addr, "tcp://", "", 1)
			var conn net.Conn
			conn, err = net.Dial("tcp", address)
			modConfig.SetAddrType(loggerTypeTcp)
			//modConfig.SetLoggerTCPAddr(address)
			writer = conn
		} else {
			var f *os.File
			f, err = os.Create(addr)
			modConfig.SetAddrType(loggerTypeFile)
			//modConfig.SetLoggerTCPAddr("")
			writer = f
		}
		if err == nil && writer != nil {
			multi := zerolog.MultiLevelWriter(consoleWriter, writer)
			logger = zerolog.New(multi).With().Timestamp().Logger()
		} else {
			logger.Warn().Err(err).Msg("failed to create multiLogger")
		}
	}
	return logger
}

// runModule run module
func runModule(modName string, modConfig config.IConfig) {
	var err error
	setModConfig(globalConf, modConfig)
	var logger = initLogger(globalConf.LoggerAddr, modConfig)
	var eventCollector zerolog.Logger
	if globalConf.EventCollectorAddr == "" {
		eventCollector = logger
	} else {
		eventCollector = initLogger(globalConf.EventCollectorAddr, modConfig)
	}
	var ecw = eventCollectorWriter{logger: &eventCollector}
	// init eCapture
	logger.Info().Str("AppName", fmt.Sprintf("%s(%s)", CliName, CliNameZh)).Send()
	logger.Info().Str("HomePage", CliHomepage).Send()
	logger.Info().Str("Repository", CliRepo).Send()
	logger.Info().Str("Author", CliAuthor).Send()
	logger.Info().Str("Description", CliDescription).Send()
	logger.Info().Str("Version", GitVersion).Send()

	logger.Info().Str("Listen", globalConf.Listen).Send()
	logger.Info().Str("logger", globalConf.LoggerAddr).Msg("eCapture running logs")
	logger.Info().Str("eventCollector", globalConf.EventCollectorAddr).Msg("the file handler that receives the captured event")

	var isReload bool
	var reRloadConfig = make(chan config.IConfig, 10)

	// listen http server
	go func() {
		logger.Info().Str("listen", globalConf.Listen).Send()
		logger.Info().Msg("https server starting...You can update the configuration file via the HTTP interface.")
		var ec = http.NewHttpServer(globalConf.Listen, reRloadConfig, logger)
		err = ec.Run()
		if err != nil {
			logger.Fatal().Err(err).Msg("http server start failed")
			return
		}
	}()

	// run module
	{
		// config check
		err = modConfig.Check()
		if err != nil {
			logger.Fatal().Err(err).Msg("config check failed")
		}
		modFunc := module.GetModuleFunc(modName)
		if modFunc == nil {
			logger.Fatal().Err(fmt.Errorf("cant found module function: %s", modName)).Send()
		}

	reload:
		// 初始化
		logger.Warn().Msg("========== module starting. ==========")
		mod := modFunc()
		ctx, cancelFun := context.WithCancel(context.TODO())
		err = mod.Init(ctx, &logger, modConfig, ecw)
		if err != nil {
			logger.Fatal().Err(err).Bool("isReload", isReload).Msg("module initialization failed")
		}
		logger.Info().Str("moduleName", modName).Bool("isReload", isReload).Msg("module initialization.")

		err = mod.Run()
		if err != nil {
			logger.Fatal().Err(err).Bool("isReload", isReload).Msg("module run failed, skip it.")
		}
		logger.Info().Str("moduleName", modName).Bool("isReload", isReload).Msg("module started successfully.")

		// reset isReload
		isReload = false
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		select {
		case _, ok := <-stopper:
			if !ok {
				logger.Warn().Msg("reload stopper channel closed.")
				break
			}
			isReload = false
		case rc, ok := <-reRloadConfig:
			if !ok {
				logger.Warn().Msg("reload config channel closed.")
				isReload = false
				break
			}
			logger.Warn().Msg("========== Signal received; the module will initiate a restart. ==========")
			isReload = true
			modConfig = rc
		}
		cancelFun()
		// clean up
		err = mod.Close()
		if err != nil {
			logger.Warn().Err(err).Msg("module close failed")
		}
		// reload
		if isReload {
			isReload = false
			logger.Info().RawJSON("config", modConfig.Bytes()).Msg("reloading module...")
			goto reload
		}
	}

	// TODO Stop http server

	logger.Info().Msg("bye bye.")
}
