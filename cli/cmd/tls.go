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
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"ecapture/pkg/util/kernel"
	"ecapture/user/config"
	"ecapture/user/module"

	"github.com/spf13/cobra"
)

var oc = config.NewOpensslConfig()

// opensslCmd represents the openssl command
var opensslCmd = &cobra.Command{
	Use:     "tls",
	Aliases: []string{"openssl"},
	Short:   "use to capture tls/ssl text content without CA cert. (Support openssl 1.0.x/1.1.x/3.0.x or newer).",
	Long: `use eBPF uprobe/TC to capture process event data and network data.also support pcap-NG format.

ecapture tls -m [text|keylog|pcap] [flags] [pcap filter expression (for pcap mode)]
ecapture tls -m pcap -i wlan0 -w save.pcapng host 192.168.1.1 and tcp port 443
ecapture tls -l save.log --pid=3423
ecapture tls --libssl=/lib/x86_64-linux-gnu/libssl.so.1.1
ecapture tls -m keylog --pcapfile save_3_0_5.pcapng --ssl_version="openssl 3.0.5" --libssl=/lib/x86_64-linux-gnu/libssl.so.3
ecapture tls -m pcap --pcapfile save_android.pcapng -i wlan0 --libssl=/apex/com.android.conscrypt/lib64/libssl.so --ssl_version="boringssl 1.1.1" tcp port 443
`,
	Run: openSSLCommandFunc,
}

func init() {
	// opensslCmd.PersistentFlags().StringVar(&oc.Curlpath, "curl", "", "curl or wget file path, use to dectet openssl.so path, default:/usr/bin/curl. (Deprecated)")
	opensslCmd.PersistentFlags().StringVar(&oc.Openssl, "libssl", "", "libssl.so file path, will automatically find it from curl default.")
	opensslCmd.PersistentFlags().StringVar(&oc.CGroupPath, "cgroup_path", "/sys/fs/cgroup", "cgroup path, default: /sys/fs/cgroup.")
	opensslCmd.PersistentFlags().StringVar(&oc.Pthread, "pthread", "", "libpthread.so file path, use to hook connect to capture socket FD.will automatically find it from curl.")
	opensslCmd.PersistentFlags().StringVarP(&oc.Model, "model", "m", "text", "capture model, such as : text, pcap/pcapng, key/keylog")
	opensslCmd.PersistentFlags().StringVarP(&oc.KeylogFile, "keylogfile", "k", "ecapture_openssl_key.og", "The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.")
	opensslCmd.PersistentFlags().StringVarP(&oc.PcapFile, "pcapfile", "w", "save.pcapng", "write the raw packets to file as pcapng format.")
	opensslCmd.PersistentFlags().StringVarP(&oc.Ifname, "ifname", "i", "", "(TC Classifier) Interface name on which the probe will be attached.")
	opensslCmd.PersistentFlags().StringVar(&oc.SslVersion, "ssl_version", "", "openssl/boringssl version， e.g: --ssl_version=\"openssl 1.1.1g\" or  --ssl_version=\"boringssl 1.1.1\"")

	rootCmd.AddCommand(opensslCmd)
}

// openSSLCommandFunc executes the "bash" command.
func openSSLCommandFunc(command *cobra.Command, args []string) {
	if oc.PcapFilter == "" && len(args) != 0 {
		oc.PcapFilter = strings.Join(args, " ")
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	logger := log.New(os.Stdout, "tls_", log.LstdFlags)

	// save global config
	gConf, err := getGlobalConf(command)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetOutput(gConf.writer)

	logger.Printf("ECAPTURE :: %s Version : %s", cliName, GitVersion)
	logger.Printf("ECAPTURE :: Pid Info : %d", os.Getpid())
	var version kernel.Version
	version, _ = kernel.HostVersion() // it's safe to ignore err because we have checked it in func main
	logger.Printf("ECAPTURE :: Kernel Info : %s", version.String())
	modNames := []string{module.ModuleNameOpenssl}

	var runMods uint8
	runModules := make(map[string]module.IModule)
	var wg sync.WaitGroup

	for _, modName := range modNames {
		mod := module.GetModuleByName(modName)
		if mod == nil {
			logger.Printf("ECAPTURE :: \tcant found module: %s", modName)
			break
		}
		if oc == nil {
			logger.Printf("ECAPTURE :: \tcant found module %s config info.", mod.Name())
			break
		}
		var conf config.IConfig
		conf = oc

		conf.SetPid(gConf.Pid)
		conf.SetUid(gConf.Uid)
		conf.SetDebug(gConf.Debug)
		conf.SetHex(gConf.IsHex)
		conf.SetPerCpuMapSize(gConf.mapSizeKB)
		err = conf.Check()

		if err != nil {
			logger.Printf("%s\tmodule initialization failed. [skip it]. error:%+v", mod.Name(), err)
			continue
		}

		logger.Printf("%s\tmodule initialization", mod.Name())

		// 初始化
		err = mod.Init(ctx, logger, conf)
		if err != nil {
			logger.Printf("%s\tmodule initialization failed, [skip it]. error:%+v", mod.Name(), err)
			continue
		}

		// 加载ebpf，挂载到hook点上，开始监听
		//go func(module user.IModule) {
		//
		//}(mod)
		err = mod.Run()
		if err != nil {
			logger.Printf("%s\tmodule run failed, [skip it]. error:%+v", mod.Name(), err)
			continue
		}
		runModules[mod.Name()] = mod
		logger.Printf("%s\tmodule started successfully.", mod.Name())
		wg.Add(1)
		runMods++
	}

	// needs runmods > 0
	if runMods > 0 {
		logger.Printf("ECAPTURE :: \tstart %d modules", runMods)
		<-stopper
	} else {
		logger.Println("ECAPTURE :: \tNo runnable modules, Exit(1)")
		os.Exit(1)
	}
	cancelFun()

	// clean up
	for _, mod := range runModules {
		err = mod.Close()
		wg.Done()
		if err != nil {
			logger.Fatalf("%s\tmodule close failed. error:%+v", mod.Name(), err)
		}
	}

	wg.Wait()
	os.Exit(0)
}
