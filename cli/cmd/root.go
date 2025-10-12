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
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gojue/ecapture/pkg/ecaptureq"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/cli/cobrautl"
	"github.com/gojue/ecapture/cli/http"
	"github.com/gojue/ecapture/pkg/util/roratelog"
	"github.com/gojue/ecapture/pkg/util/ws"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/gojue/ecapture/user/module"
)

const (
	CliName        = "eCapture"
	CliNameZh      = "旁观者"
	CliDescription = "Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supported on Linux/Android kernels for amd64/arm64."
	CliHomepage    = "https://ecapture.cc"
	CliAuthor      = "CFC4N <cfc4ncs@gmail.com>"
	CliGithubRepo  = "https://github.com/gojue/ecapture"
)

var (
	// GitVersion default value, eg: linux_arm64:v0.8.10-20241116-fcddaeb:5.15.0-125-generic
	GitVersion = "os_arch:v0.0.0-20221111-develop:default_kernel"
	//ReleaseDate = "2022-03-16"
	ByteCodeFiles = "all" // Indicates the type of bytecode files built by the project, i.e., the file types under the assets/* folder. Default is "all", meaning both types are included.
	rorateSize    = uint16(0)
	rorateTime    = uint16(0)
)

const (
	defaultPid          uint64 = 0
	defaultUid          uint64 = 0
	defaultTruncateSize uint64 = 0
)

const (
	loggerTypeStdout    uint8 = 0
	loggerTypeFile      uint8 = 1
	loggerTypeTcp       uint8 = 2
	loggerTypeWebsocket uint8 = 3
)

// ListenPort1 or ListenPort2 are the default ports for the http server.
const (
	configUpdateAddr = "localhost:28256"
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
	rootCmd.PersistentFlags().StringVarP(&globalConf.LoggerAddr, "logaddr", "l", "", "send logs to this server. -l /tmp/ecapture.log or -l ws://127.0.0.1:8090/ecapture or -l tcp://127.0.0.1:8080")
	rootCmd.PersistentFlags().StringVar(&globalConf.EventCollectorAddr, "eventaddr", "", "the server address that receives the captured event. --eventaddr ws://127.0.0.1:8090/ecapture or tcp://127.0.0.1:8090, default: same as logaddr")
	rootCmd.PersistentFlags().StringVar(&globalConf.EcaptureQ, "ecaptureq", "", "listening server, waiting for clients to connect before sending events and logs; false: send directly to the remote server.")
	rootCmd.PersistentFlags().StringVar(&globalConf.Listen, "listen", configUpdateAddr, "Listens on a port, receives HTTP requests, and is used to update the runtime configuration, default: 127.0.0.1:28256")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.TruncateSize, "tsize", "t", defaultTruncateSize, "the truncate size in text mode, default: 0 (B), no truncate")
	rootCmd.PersistentFlags().Uint16Var(&rorateSize, "eventroratesize", 0, "the rorate size(MB) of the event collector file, 1M~65535M, only works for eventaddr server is file. --eventaddr=tls.log --eventroratesize=1 --eventroratetime=30")
	rootCmd.PersistentFlags().Uint16Var(&rorateTime, "eventroratetime", 0, "the rorate time(s) of the event collector file, 1s~65535s, only works for eventaddr server is file. --eventaddr=tls.log --eventroratesize=1 --eventroratetime=30")
	rootCmd.SilenceUsage = true
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
	modConf.SetTruncateSize(globalConf.TruncateSize)

	switch ByteCodeFiles {
	case "core":
		modConf.SetByteCodeFileMode(config.ByteCodeFileCore)
	case "noncore":
		modConf.SetByteCodeFileMode(config.ByteCodeFileNonCore)
	default:
		modConf.SetByteCodeFileMode(config.ByteCodeFileAll)
	}
}

// initLogger init logger
func initLogger(addr string, modConfig config.IConfig, isRorate bool) (zerolog.Logger, error) {
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
			if err != nil {
				return zerolog.Logger{}, err
			}
			modConfig.SetAddrType(loggerTypeTcp)
			//modConfig.SetLoggerTCPAddr(address)
			writer = conn
		} else if strings.Contains(addr, "ws://") || strings.Contains(addr, "wss://") {
			// 验证URL协议是否为ws或wss
			parsedURL, err := url.Parse(addr)
			if err != nil {
				return zerolog.Logger{}, err
			}

			if parsedURL.Scheme != "ws" && parsedURL.Scheme != "wss" {
				return zerolog.Logger{}, errors.New("URL scheme must be 'ws' or 'wss'")
			}

			modConfig.SetAddrType(loggerTypeWebsocket)
			// 连接到WebSocket服务器
			var wsConn = ws.NewClient()
			err = wsConn.Dial(addr, "", "http://localhost")
			if err != nil {
				return zerolog.Logger{}, fmt.Errorf("failed to connect to WebSocket server: %s", err.Error())
			}
			writer = wsConn
		} else {
			modConfig.SetAddrType(loggerTypeFile)
			//modConfig.SetLoggerTCPAddr("")
			isLogRate := isRorate && (rorateSize > 0 || rorateTime > 0)
			if isLogRate {
				logFile := &roratelog.Logger{
					Filename:    addr,
					MaxSize:     int(rorateSize), // MB
					MaxInterval: time.Duration(rorateTime) * time.Second,
					LocalTime:   true,
				}
				writer = logFile
			} else {
				var f *os.File
				f, err = os.Create(addr)
				writer = f
			}
		}

		if err == nil && writer != nil {
			multi := zerolog.MultiLevelWriter(consoleWriter, writer)
			logger = zerolog.New(multi).With().Timestamp().Logger()
		} else {
			//logger.Warn().Err(err).Msg("failed to create multiLogger")
			return zerolog.Logger{}, errors.New("failed to create multiLogger")
		}
	}
	return logger, nil
}

// runModule run module
func runModule(modName string, modConfig config.IConfig) error {
	setModConfig(globalConf, modConfig)
	var logger, eventCollector zerolog.Logger
	var err error
	var ecw io.Writer
	if globalConf.EcaptureQ != "" {
		parsedURL, err := url.Parse(globalConf.EcaptureQ)
		if err != nil {
			return err
		}
		es := ecaptureq.NewServer(parsedURL.Host, os.Stdout)
		go func() {
			err := es.Start()
			if err != nil {
				fmt.Printf("eCaptureQ addr listen failed:%s\n", err.Error())
				os.Exit(1)
				return
			}
		}()
		// log writer
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if modConfig.GetDebug() {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		eqWriter := ecaptureQLogWriter{es: es}

		multi := zerolog.MultiLevelWriter(consoleWriter, eqWriter)
		logger = zerolog.New(multi).With().Timestamp().Logger()

		ecw = ecaptureQEventWriter{es: es}
	} else {
		logger, err = initLogger(globalConf.LoggerAddr, modConfig, false)
		if err != nil {
			return err
		}
		if globalConf.EventCollectorAddr == "" {
			eventCollector = logger
		} else {
			eventCollector, err = initLogger(globalConf.EventCollectorAddr, modConfig, true)
			if err != nil {
				return err
			}
		}
		ecw = event.NewCollectorWriter(&eventCollector)
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
	logger.Info().Str("eventCollector", globalConf.EventCollectorAddr).Msg("the file handler that receives the captured event")

	var isReload bool
	var reRloadConfig = make(chan config.IConfig, 10)

	// listen http server
	go func() {
		logger.Info().Str("listen", globalConf.Listen).Send()
		logger.Info().Msg("https server starting...You can upgrade the configuration file via the HTTP interface.")
		var ec = http.NewHttpServer(globalConf.Listen, reRloadConfig, logger)
		err = ec.Run()
		if err != nil {
			logger.Fatal().Err(err).Msg("http server start failed")
			return
		}
	}()

	ctx, cancelFun := context.WithCancel(context.TODO())

	// upgrade check
	go func() {
		tags, upgradeUrl, e := upgradeCheck(ctx)
		if e != nil {
			logger.Debug().Msgf("upgrade check failed: %s", e.Error())
			return
		}
		logger.Warn().Msgf("A new version %s is available:%s", tags, upgradeUrl)
	}()

	// run module
	{
		// config check
		err = modConfig.Check()
		if err != nil {
			logger.Fatal().Err(err).Msg("config check failed")
			//return fmt.Errorf("config check failed: %s", err.Error())
		}
		modFunc := module.GetModuleFunc(modName)
		if modFunc == nil {
			logger.Fatal().Err(fmt.Errorf("cant found module function: %s", modName)).Send()
		}

	reload:
		// 初始化
		mod := modFunc()
		err = mod.Init(ctx, &logger, modConfig, ecw)
		if err != nil {
			logger.Fatal().Err(err).Bool("isReload", isReload).Msg("module initialization failed")
		}
		logger.Info().Str("moduleName", modName).Bool("isReload", isReload).Msg("module initialization.")

		err = mod.Run()
		if err != nil {
			logger.Fatal().Err(err).Bool("isReload", isReload).Msg("module run failed.")
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
	return nil
}
