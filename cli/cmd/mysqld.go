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

var mysqldConfig = config.NewMysqldConfig()

// mysqldCmd represents the mysqld command
var mysqldCmd = &cobra.Command{
	Use:   "mysqld",
	Short: "capture sql queries from mysqld 5.6/5.7/8.0 .",
	Long: ` only support mysqld 5.6/5.7/8.0 and mariadDB 10.5+.

other version coming soon`,
	Run: mysqldCommandFunc,
}

func init() {
	mysqldCmd.PersistentFlags().StringVarP(&mysqldConfig.Mysqldpath, "mysqld", "m", "/usr/sbin/mariadbd", "mysqld binary file path, use to hook")
	mysqldCmd.PersistentFlags().Uint64VarP(&mysqldConfig.Offset, "offset", "", 0, "0x710410")
	mysqldCmd.PersistentFlags().StringVarP(&mysqldConfig.FuncName, "funcname", "f", "", "function name to hook")
	rootCmd.AddCommand(mysqldCmd)
}

// mysqldCommandFunc executes the "mysqld" command.
func mysqldCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	mod := module.GetModuleByName(module.ModuleNameMysqld)

	logger := log.New(os.Stdout, "mysqld_", log.LstdFlags)
	logger.Printf("ECAPTURE :: version :%s", GitVersion)
	logger.Printf("ECAPTURE :: start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	logger.SetOutput(gConf.writer)
	mysqldConfig.Pid = gConf.Pid
	mysqldConfig.Debug = gConf.Debug
	mysqldConfig.IsHex = gConf.IsHex

	log.Printf("ECAPTURE :: pid info :%d", os.Getpid())
	//bc.Pid = globalFlags.Pid
	if e := mysqldConfig.Check(); e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}

	//初始化
	err := mod.Init(ctx, logger, mysqldConfig)
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
