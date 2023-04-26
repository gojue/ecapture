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
	"ecapture/pkg/util/kernel"
	"ecapture/user/config"
	"ecapture/user/module"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var goc = config.NewGoTLSConfig()

// gotlsCmd represents the openssl command
var gotlsCmd = &cobra.Command{
	Use:     "gotls",
	Aliases: []string{"tlsgo"},
	Short:   "Capturing plaintext communication from Golang programs encrypted with TLS/HTTPS.",
	Long: `Utilize eBPF uprobe/TC to capture both process event and network data, with added support for pcap-NG format.
ecapture gotls
ecapture gotls --elfpath=/home/cfc4n/go_https_client --hex --pid=3423
ecapture gotls --elfpath=/home/cfc4n/go_https_client -l save.log --pid=3423
ecapture gotls -w save_android.pcapng -i wlan0 --port 443 --elfpath=/home/cfc4n/go_https_client
`,
	Run: goTLSCommandFunc,
}

func init() {
	gotlsCmd.PersistentFlags().StringVarP(&goc.Path, "elfpath", "e", "", "ELF path to binary built with Go toolchain.")
	gotlsCmd.PersistentFlags().StringVarP(&goc.Write, "write", "w", "", "write the  raw packets to file as pcapng format.")
	gotlsCmd.PersistentFlags().StringVarP(&goc.Ifname, "ifname", "i", "", "(TC Classifier) Interface name on which the probe will be attached.")
	gotlsCmd.PersistentFlags().Uint16Var(&goc.Port, "port", 443, "port number to capture, default:443.")
	rootCmd.AddCommand(gotlsCmd)
}

// goTLSCommandFunc executes the "bash" command.
func goTLSCommandFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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
	logger.Printf("ECAPTURE :: %s Version : %s", cliName, GitVersion)
	logger.Printf("ECAPTURE :: Pid Info : %d", os.Getpid())
	var version kernel.Version
	version, err = kernel.HostVersion()
	logger.Printf("ECAPTURE :: Kernel Info : %s", version.String())

	mod := module.GetModuleByName(module.ModuleNameGotls)
	if mod == nil {
		logger.Printf("ECAPTURE :: \tcant found module: %s", module.ModuleNameGotls)
		return
	}

	var conf config.IConfig
	conf = goc
	if conf == nil {
		logger.Printf("ECAPTURE :: \tcant found module %s config info.", mod.Name())
		return
	}

	conf.SetPid(gConf.Pid)
	conf.SetUid(gConf.Uid)
	conf.SetDebug(gConf.Debug)
	conf.SetHex(gConf.IsHex)
	conf.SetNoSearch(gConf.NoSearch)

	err = conf.Check()

	if err != nil {
		// ErrorGoBINNotFound is a special error, we should not print it.
		if errors.Is(err, config.ErrorGoBINNotFound) {
			logger.Printf("%s\tmodule [disabled].", mod.Name())
			return
		}

		logger.Printf("%s\tmodule initialization failed. [skip it]. error:%+v", mod.Name(), err)
		return
	}

	logger.Printf("%s\tmodule initialization", mod.Name())

	//初始化
	err = mod.Init(context.TODO(), logger, conf)
	if err != nil {
		logger.Printf("%s\tmodule initialization failed, [skip it]. error:%+v", mod.Name(), err)
		return
	}

	err = mod.Run()
	if err != nil {
		logger.Printf("%s\tmodule run failed, [skip it]. error:%+v", mod.Name(), err)
		return
	}

	logger.Printf("%s\tmodule started successfully.", mod.Name())

	<-stopper

	// clean up
	err = mod.Close()
	if err != nil {
		logger.Fatalf("%s\tmodule close failed. error:%+v", mod.Name(), err)
	}
	os.Exit(0)
}
