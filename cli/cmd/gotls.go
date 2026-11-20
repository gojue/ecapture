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

// gotlsCmd represents the gotls command
var gotlsCmd = &cobra.Command{
	Use:     "gotls",
	Aliases: []string{"tlsgo"},
	Short:   "Capturing plaintext communication from Golang programs encrypted with TLS/HTTPS.",
	Long: `Utilize eBPF uprobe/TC to capture both process event and network data, with added support for pcap-NG format.
ecapture gotls --elfpath=/path/to/go/binary -m text --text-source pcapng
ecapture gotls --elfpath=/path/to/go/binary -m text --text-source pcapng --output stdout --output capture.jsonl --pid=3423
ecapture gotls --elfpath=/path/to/go/binary -m keylog --keylogfile save.keys --output runtime.jsonl --pid=3423
ecapture gotls --elfpath=/path/to/go/binary -m pcapng --pcapfile save.pcapng -i eth0 tcp port 443
`,
	Example: `  # userland perf reorder (flag name uses hyphens, not underscores)
  ecapture gotls --elfpath=/path/to/go/binary --btf=1 --debug --perf-reorder -m text --text-source pcapng
  ecapture gotls -e /path/to/go/binary --perf-reorder --perf-reorder-lag-ms=20 -m text --text-source pcapng`,
	RunE: goTLSCommandFunc,
}

func init() {
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.ElfPath, "elfpath", "e", "", "ELF path to binary built with Go toolchain.")
	gotlsCmd.PersistentFlags().BoolVar(&globalConf.PerfReorder, "perf-reorder", false, "enable userland reorder of per-CPU perf events by bpf ktime before dispatch (see also: tls, mysqld, postgres)")
	gotlsCmd.PersistentFlags().UintVar(&globalConf.PerfReorderLagMs, "perf-reorder-lag-ms", 10, "reorder batching window in milliseconds (only with --perf-reorder; default 10)")
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.PcapFile, "pcapfile", "w", "", "local pcapng file; required in pcapng mode, optional with text-source pcapng")
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.CaptureMode, "model", "m", "text", "capture mode: text, pcap/pcapng, key/keylog")
	gotlsCmd.PersistentFlags().StringVar(&gotlsConfig.TextSource, "text-source", handlers.TextSourcePcapng, "text capture source: pcapng (live TLS decryption) or hook")
	bindDecryptFlags(gotlsCmd, &gotlsConfig.DecryptConfig)
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.KeylogFile, "keylogfile", "k", "", "local NSS keylog file; required in keylog mode, optional with text-source pcapng")
	gotlsCmd.PersistentFlags().StringVarP(&gotlsConfig.Ifname, "ifname", "i", "", "capture interface; automatically selected from default routes, then traffic counters, when omitted")
	gotlsCmd.PersistentFlags().StringVar(&globalConf.CGroupPath, "cgroup_path", "", "cgroup v2 path for container/process filtering. Empty disables cgroup filtering.")
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
