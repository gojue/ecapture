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

var mysqldConfig = user.NewMysqldConfig()

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

	mod := user.GetModuleByName(user.MODULE_NAME_MYSQLD)

	logger := log.Default()

	logger.Printf("start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	mysqldConfig.Pid = gConf.Pid
	mysqldConfig.Debug = gConf.Debug
	mysqldConfig.IsHex = gConf.IsHex

	log.Printf("pid info :%d", os.Getpid())
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
