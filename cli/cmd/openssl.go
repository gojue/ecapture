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

var oc = user.NewOpensslConfig()

// opensslCmd represents the openssl command
var opensslCmd = &cobra.Command{
	Use:   "openssl",
	Short: "捕获基于openssl类库的SSL/TLS等加密通讯的明文。",
	Long: `HOOK openssl类库的libssl.so动态链接库，并非网络层获取。

适用于运维定位、研发调试、安全审计、内容审计等业务场景。
firefox的Network Security Services (NSS)类库暂不支持，规划中。
`,
	Run: openSSLCommandFunc,
}

func init() {
	opensslCmd.PersistentFlags().StringVar(&oc.Curlpath, "curl", "", "curl or wget file path, 用于自动定位所用openssl.so的路径, default:/usr/bin/curl")
	opensslCmd.PersistentFlags().StringVar(&oc.Openssl, "libssl", "", "libssl.so file path, will automatically find it from curl default.")

	rootCmd.AddCommand(opensslCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// opensslCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// opensslCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// openSSLCommandFunc executes the "bash" command.
func openSSLCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	mod := user.GetModuleByName(user.MODULE_NAME_OPENSSL)

	logger := log.Default()

	logger.Printf("start to run %s module", mod.Name())

	// save global config
	gConf, e := getGlobalConf(command)
	if e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}
	oc.Pid = gConf.Pid
	oc.Debug = gConf.Debug
	oc.IsHex = gConf.IsHex

	log.Printf("pid info :%d", os.Getpid())
	if e := oc.Check(); e != nil {
		logger.Fatal(e)
		os.Exit(1)
	}

	//初始化
	err := mod.Init(ctx, logger, oc)
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

	// NSS网络捕获 @TODO

	<-stopper
	cancelFun()
	os.Exit(0)
}
