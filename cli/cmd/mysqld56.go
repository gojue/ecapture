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

var mc56 = user.NewMysqld56Config()

// mysqld56Cmd represents the mysqld56 command
var mysqld56Cmd = &cobra.Command{
	Use:   "mysqld",
	Short: "capture sql queries from mysqld >5.6 .",
	Long: ` only support mysqld 5.6 / mariadDB 10.5.

other version coming soon`,
	Run: mysqld56CommandFunc,
}

func init() {
	mysqld56Cmd.PersistentFlags().StringVarP(&mc56.Mysqld56path, "mysqld", "m", "/usr/sbin/mariadbd", "mysqld binary file path, use to hook")
	mysqld56Cmd.PersistentFlags().Uint64VarP(&mc56.Offset, "offset", "", 0, "0x710410")
	mysqld56Cmd.PersistentFlags().StringVarP(&mc56.FuncName, "funcname", "f", "", "function name to hook")
	rootCmd.AddCommand(mysqld56Cmd)
}

// mysqld56CommandFunc executes the "mysqld56" command.
func mysqld56CommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	mod := user.GetModuleByName(user.MODULE_NAME_MYSQLD56)

	logger := log.Default()

	logger.Printf("start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	mc56.Pid = gConf.Pid
	mc56.Debug = gConf.Debug
	mc56.IsHex = gConf.IsHex

	log.Printf("pid info :%d", os.Getpid())
	//bc.Pid = globalFlags.Pid
	if e := mc56.Check(); e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}

	//初始化
	err := mod.Init(ctx, logger, mc56)
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
