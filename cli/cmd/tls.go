/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package cmd

import (
	"context"
	"ecapture/user"
	"errors"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
)

var oc = user.NewOpensslConfig()
var gc = user.NewGnutlsConfig()
var nc = user.NewNsprConfig()
var goc = user.NewGoSSLConfig()

// opensslCmd represents the openssl command
var opensslCmd = &cobra.Command{
	Use:     "tls",
	Aliases: []string{"openssl", "gnutls", "nss"},
	Short:   "alias name:openssl , use to capture tls/ssl text content without CA cert.",
	Long: `use eBPF uprobe to capture process event data, not used libpcap.
Can used to trace, debug, database audit, security event aduit etc.
`,
	Run: openSSLCommandFunc,
}

func init() {
	opensslCmd.PersistentFlags().StringVar(&oc.Curlpath, "curl", "", "curl or wget file path, use to dectet openssl.so path, default:/usr/bin/curl")
	opensslCmd.PersistentFlags().StringVar(&oc.Openssl, "libssl", "", "libssl.so file path, will automatically find it from curl default.")
	opensslCmd.PersistentFlags().StringVar(&gc.Gnutls, "gnutls", "", "libgnutls.so file path, will automatically find it from curl default.")
	opensslCmd.PersistentFlags().StringVar(&gc.Curlpath, "wget", "", "wget file path, default: /usr/bin/wget.")
	opensslCmd.PersistentFlags().StringVar(&nc.Firefoxpath, "firefox", "", "firefox file path, default: /usr/lib/firefox/firefox.")
	opensslCmd.PersistentFlags().StringVar(&nc.Nsprpath, "nspr", "", "libnspr44.so file path, will automatically find it from curl default.")
	opensslCmd.PersistentFlags().StringVar(&oc.Pthread, "pthread", "", "libpthread.so file path, use to hook connect to capture socket FD.will automatically find it from curl.")
	opensslCmd.PersistentFlags().StringVar(&goc.Path, "gobin", "", "path to binary built with Go toolchain.")
	opensslCmd.PersistentFlags().StringVarP(&oc.Write, "write", "w", "", "write the  raw packets to file as pcapng format.")
	opensslCmd.PersistentFlags().StringVarP(&oc.Ifname, "ifname", "i", "", "(TC Classifier) Interface name on which the probe will be attached.")
	opensslCmd.PersistentFlags().Uint16Var(&oc.Port, "port", 443, "port number to capture, default:443.")

	rootCmd.AddCommand(opensslCmd)
}

// openSSLCommandFunc executes the "bash" command.
func openSSLCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	logger := log.New(os.Stdout, "tls_", log.LstdFlags)

	// save global config
	gConf, err := getGlobalConf(command)
	if err != nil {
		logger.Fatal(err)
	}
	if gConf.loggerFile != "" {
		f, e := os.Create(gConf.loggerFile)
		if e != nil {
			logger.Fatal(e)
			return
		}
		logger.SetOutput(f)
	}
	logger.Printf("ECAPTURE :: pid info :%d", os.Getpid())

	modNames := []string{user.MODULE_NAME_OPENSSL, user.MODULE_NAME_GNUTLS, user.MODULE_NAME_NSPR, user.MODULE_NAME_GOSSL}

	var runMods uint8
	var runModules = make(map[string]user.IModule)
	var wg sync.WaitGroup

	for _, modName := range modNames {
		mod := user.GetModuleByName(modName)
		if mod == nil {
			logger.Printf("ECAPTURE :: \tcant found module: %s", modName)
			break
		}

		var conf user.IConfig
		switch mod.Name() {
		case user.MODULE_NAME_OPENSSL:
			conf = oc
		case user.MODULE_NAME_GNUTLS:
			conf = gc
		case user.MODULE_NAME_NSPR:
			conf = nc
		case user.MODULE_NAME_GOSSL:
			conf = goc
		default:
		}

		if conf == nil {
			logger.Printf("ECAPTURE :: \tcant found module %s config info.", mod.Name())
			break
		}

		conf.SetPid(gConf.Pid)
		conf.SetUid(gConf.Uid)
		conf.SetDebug(gConf.Debug)
		conf.SetHex(gConf.IsHex)
		conf.SetNoSearch(gConf.NoSearch)

		err := conf.Check()

		if err != nil {
			// ErrorGoBINNotSET is a special error, we should not print it.
			if errors.Is(err, user.ErrorGoBINNotSET) {
				logger.Printf("%s\tmodule [disabled].", mod.Name())
				continue
			}

			logger.Printf("%s\tmodule initialization failed. [skip it]. error:%+v", mod.Name(), err)
			continue
		}

		logger.Printf("%s\tmodule initialization", mod.Name())

		//初始化
		err = mod.Init(ctx, logger, conf)
		if err != nil {
			logger.Printf("%s\tmodule initialization failed, [skip it]. error:%+v", mod.Name(), err)
			continue
		}

		// 加载ebpf，挂载到hook点上，开始监听
		go func(module user.IModule) {
			err := module.Run()
			if err != nil {
				logger.Printf("%s\tmodule run failed, [skip it]. error:%+v", module.Name(), err)
				return
			}
		}(mod)
		runModules[mod.Name()] = mod
		logger.Printf("%s\tmodule started successfully.", mod.Name())
		wg.Add(1)
		runMods++
	}

	// needs runmods > 0
	if runMods > 0 {
		<-stopper
	}
	cancelFun()

	// clean up
	for _, mod := range runModules {
		err = mod.Close()
		if err != nil {
			logger.Fatalf("%s\tmodule close failed. error:%+v", mod.Name(), err)
		}
		wg.Done()
	}

	wg.Wait()
	os.Exit(0)
}
