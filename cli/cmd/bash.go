/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package cmd

import (
	"context"
	"ecapture/user"
	"github.com/spf13/cobra"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var bc = user.NewBashConfig()

// bashCmd represents the bash command
var bashCmd = &cobra.Command{
	Use:   "bash",
	Short: "capture bash command",
	Long:  `捕获bash命令，用于bash审计场景。会自动查找当前env的bash，作为捕获目标。`,
	Run:   bashCommandFunc,
}

func init() {
	bashCmd.PersistentFlags().StringVar(&bc.Bashpath, "bash", "", "$SHELL file path, eg: /bin/bash , will automatically find it from $ENV default.")
	bashCmd.PersistentFlags().StringVar(&bc.Readline, "readlineso", "", "readline.so file path, will automatically find it from $BASH_PATH default.")
	rootCmd.AddCommand(bashCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// bashCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// bashCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// bashCommandFunc executes the "bash" command.
func bashCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	mod := user.GetModuleByName(user.MODULE_NAME_BASH)

	logger := log.Default()

	logger.Printf("start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	bc.Pid = gConf.Pid
	bc.Debug = gConf.Debug
	bc.IsHex = gConf.IsHex

	log.Printf("pid info :%d", os.Getpid())
	//bc.Pid = globalFlags.Pid
	if e := bc.Check(); e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}

	//初始化
	err := mod.Init(ctx, logger, bc)
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
