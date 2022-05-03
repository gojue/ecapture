/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package cmd

import (
	"context"
	"ecapture/user"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var postgresConfig = user.NewPostgresConfig()

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

	mod := user.GetModuleByName(user.MODULE_NAME_POSTGRES)

	logger := log.Default()

	logger.Printf("start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	postgresConfig.Pid = gConf.Pid
	postgresConfig.Debug = gConf.Debug
	postgresConfig.IsHex = gConf.IsHex

	log.Printf("pid info: %d", os.Getpid())
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
	go func(module user.IModule) {
		err := module.Run()
		if err != nil {
			logger.Fatalf("%v", err)
		}
	}(mod)
	<-stopper
	cancelFun()
	os.Exit(0)
}
