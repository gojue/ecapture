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
	defaultPid uint64 = 0
	defaultUid uint64 = 0
)

const (
	loggerTypeStdout = 0
	loggerTypeFile   = 1
	loggerTypeTcp    = 2
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:        config.CliName,
	Short:      config.CliDescription,
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
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func usageFunc(c *cobra.Command) error {
	return cobrautl.UsageFunc(c, config.GitVersion)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SetUsageFunc(usageFunc)
	rootCmd.SetHelpTemplate(`{{.UsageString}}`)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Version = config.GitVersion
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
	rootCmd.PersistentFlags().BoolVarP(&globalConf.Debug, "debug", "d", false, "enable debug logging.(coming soon)")
	rootCmd.PersistentFlags().Uint8VarP(&globalConf.BtfMode, "btf", "b", 0, "enable BTF mode.(0:auto; 1:core; 2:non-core)")
	rootCmd.PersistentFlags().BoolVar(&globalConf.IsHex, "hex", false, "print byte strings as hex encoded strings")
	rootCmd.PersistentFlags().IntVar(&globalConf.PerCpuMapSize, "mapsize", 1024, "eBPF map size per CPU,for events buffer. default:1024 * PAGESIZE. (KB)")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Pid, "pid", "p", defaultPid, "if pid is 0 then we target all pids")
	rootCmd.PersistentFlags().Uint64VarP(&globalConf.Uid, "uid", "u", defaultUid, "if uid is 0 then we target all users")
	rootCmd.PersistentFlags().StringVarP(&globalConf.LoggerAddr, "logaddr", "l", "", "-l /tmp/ecapture.log or -l tcp://127.0.0.1:8080")
}

func setModConfig(globalConf config.BaseConfig, modConf config.IConfig) error {
	modConf.SetPid(globalConf.Pid)
	modConf.SetUid(globalConf.Uid)
	modConf.SetDebug(globalConf.Debug)
	modConf.SetHex(globalConf.IsHex)
	modConf.SetBTF(globalConf.BtfMode)
	modConf.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	modConf.SetAddrType(loggerTypeStdout)
	return nil
}

func runModule(modName string, modConfig config.IConfig) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	var logger zerolog.Logger
	var err error
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	if globalConf.LoggerAddr != "" {
		var writer io.Writer
		var address string
		if strings.Contains(globalConf.LoggerAddr, "tcp://") {
			address = strings.Replace(globalConf.LoggerAddr, "tcp://", "", 1)
			var conn net.Conn
			conn, err = net.Dial("tcp", address)
			modConfig.SetAddrType(loggerTypeTcp)
			modConfig.SetAddress(address)
			writer = conn
		} else {
			address = globalConf.LoggerAddr
			var f *os.File
			f, err = os.Create(address)
			modConfig.SetAddrType(loggerTypeFile)
			modConfig.SetAddress(address)
			writer = f
		}
		if err == nil && writer != nil {
			multi := zerolog.MultiLevelWriter(consoleWriter, writer)
			logger = zerolog.New(multi).With().Timestamp().Logger()
		} else {
			logger.Warn().Err(err).Msg("failed to create logger")
		}
	}

	mod := module.GetModuleByName(modName)
	if mod == nil {
		logger.Fatal().Err(fmt.Errorf("cant found module: %s", modName)).Send()
	}
	err = setModConfig(globalConf, modConfig)
	if err != nil {
		logger.Fatal().Err(err).Send()
	}
	err = modConfig.Check()
	if err != nil {
		logger.Fatal().Err(err).Msg("module initialization failed")
	}

	// 初始化
	ctx, cancelFun := context.WithCancel(context.TODO())
	err = mod.Init(ctx, &logger, modConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("module initialization failed")
	}
	logger.Info().Str("moduleName", modName).Msg("module initialization.")

	err = mod.Run()
	if err != nil {
		logger.Fatal().Err(err).Msg("module run failed, skip it.")
	}
	logger.Info().Str("moduleName", modName).Msg("module started successfully.")

	<-stopper
	cancelFun()
	// clean up
	err = mod.Close()
	if err != nil {
		logger.Warn().Err(err).Msg("module close failed")
	}
	logger.Info().Msg("bye bye.")
	//os.Exit(0)
}
