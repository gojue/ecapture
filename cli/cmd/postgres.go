//go:build !androidgki
// +build !androidgki

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
	"ecapture/user/config"
	"ecapture/user/module"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var postgresConfig = config.NewPostgresConfig()

//postgres Cmd represents the postgres command
var postgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "capture sql queries from postgres 10+.",
	Run:   postgresCommandFunc,
}

func init() {
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.PostgresPath, "postgres", "m", "/usr/bin/postgres", "postgres binary file path, use to hook")
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.FuncName, "funcname", "f", "", "function name to hook")
	rootCmd.AddCommand(postgresCmd)
}

// postgres CommandFunc executes the "psql" command.
func postgresCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	mod := module.GetModuleByName(module.MODULE_NAME_POSTGRES)

	logger := log.New(os.Stdout, "postgress_", log.LstdFlags)
	logger.Printf("ECAPTURE :: version :%s", GitVersion)
	logger.Printf("ECAPTURE :: start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	postgresConfig.Pid = gConf.Pid
	postgresConfig.Debug = gConf.Debug
	postgresConfig.IsHex = gConf.IsHex

	log.Printf("ECAPTURE :: pid info: %d", os.Getpid())
	//bc.Pid = globalFlags.Pid
	if e := postgresConfig.Check(); e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	// init
	err := mod.Init(ctx, logger, postgresConfig)
	if err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}

	// 加载ebpf，挂载到hook点上，开始监听
	go func(module module.IModule) {
		err := module.Run()
		if err != nil {
			logger.Fatalf("%v", err)
		}
	}(mod)
	<-stopper
	cancelFun()
	os.Exit(0)
}
