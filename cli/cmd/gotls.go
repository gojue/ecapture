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
	"strings"

	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/v2/internal/factory"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
	gotlsProbe "github.com/gojue/ecapture/v2/internal/probe/gotls"
)

var gotlsConfig = gotlsProbe.NewConfig()

// gotlsCmd represents the gotls command.
var gotlsCmd = &cobra.Command{
	Use:     "gotls --elfpath <executable> [flags] [pcap filter expression]",
	Aliases: []string{"tlsgo"},
	Short:   "Capture TLS traffic from Go programs that use crypto/tls",
	Long:    tlsCaptureHelp,
	Example: `ecapture gotls --elfpath ./server --model text --text-source pcapng
ecapture gotls --elfpath ./server --model text --text-source pcapng -i lo 'tcp port 8443'
ecapture gotls --elfpath ./server --model keylog --keylogfile capture.keys
ecapture gotls --elfpath ./server --model pcapng --pcapfile capture.pcapng -i eth0`,
	RunE: goTLSCommandFunc,
}

func init() {
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.ElfPath, "elfpath", "e", "", "Path to the Go ELF executable to trace (required)")
	gotlsCmd.PersistentFlags().BoolVar(&globalConf.PerfReorder, "perf-reorder", false, perfReorderHelp)
	gotlsCmd.PersistentFlags().UintVar(&globalConf.PerfReorderLagMs, "perf-reorder-lag-ms", 10, perfReorderLagHelp)
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.PcapFile, "pcapfile", "w", "", tlsPcapFileHelp)
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.CaptureMode, "model", "m", "text", tlsModeHelp)
	gotlsCmd.PersistentFlags().StringVar(&gotlsConfig.TextSource, "text-source", handlers.TextSourcePcapng, tlsTextSourceHelp)
	bindDecryptFlags(gotlsCmd, &gotlsConfig.DecryptConfig)
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.KeylogFile, "keylogfile", "k", "", tlsKeylogFileHelp)
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.Ifname, "ifname", "i", "", tlsIfnameHelp)
	gotlsCmd.PersistentFlags().StringVar(&globalConf.CGroupPath, "cgroup_path", "", tlsCgroupHelp)
	rootCmd.AddCommand(gotlsCmd)
}

// goTLSCommandFunc executes the "gotls" command using the new probe architecture.
func goTLSCommandFunc(command *cobra.Command, args []string) error {
	if err := normalizeTLSOutputFlags(command, gotlsConfig.CaptureMode, &gotlsConfig.TextSource, &gotlsConfig.KeylogFile, &gotlsConfig.PcapFile); err != nil {
		return err
	}
	if gotlsConfig.PcapFilter == "" && len(args) != 0 {
		gotlsConfig.PcapFilter = strings.Join(args, " ")
	}

	// Run probe using the common entry point
	return runConfiguredProbe(factory.ProbeTypeGoTLS, gotlsConfig)
}
