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
	opensslProbe "github.com/gojue/ecapture/v2/internal/probe/openssl"
)

var opensslConfig = opensslProbe.NewConfig()

// These modes and packet capture options are shared by the three TLS commands.
const (
	tlsCaptureHelp = `By default, eCapture decrypts live packets and displays decoded application messages.
Text decoding options apply only to --model text --text-source pcapng.

Use keylog mode to save TLS secrets in NSS key log format, or pcapng mode to save
packets and secrets together. An optional pcap filter expression limits the packets
captured in pcapng mode or with --text-source pcapng.`
	tlsModeHelp       = "Capture `mode` (text, keylog, or pcapng). The aliases key and pcap select keylog and pcapng."
	tlsTextSourceHelp = "Text `source` (pcapng decrypts live packets, hook reads plaintext from TLS function calls)"
	tlsKeylogFileHelp = "Local NSS key log file or FIFO `path` (required in keylog mode, optional in pcapng mode or with --text-source pcapng)"
	tlsPcapFileHelp   = "Local pcapng file or FIFO `path` (required in pcapng mode, optional with --text-source pcapng)"
	tlsIfnameHelp     = "Capture packets on this `interface`. Automatic selection prefers an active Ethernet interface on the default route, then uses traffic counters."
	tlsCgroupHelp     = "Filter processes by cgroup v2 `directory` (requires kernel 5.2 or later)"
)

// opensslCmd represents the tls command.
var opensslCmd = &cobra.Command{
	Use:     "tls [flags] [pcap filter expression]",
	Aliases: []string{"openssl"},
	Short:   "Capture TLS traffic from applications that use OpenSSL or BoringSSL",
	Long:    tlsCaptureHelp,
	Example: `ecapture tls --model text --text-source pcapng -i eth0 'tcp port 443'
ecapture tls --model text --text-source pcapng --output stdout --output capture.jsonl
ecapture tls --model text --text-source pcapng --stream-listen ws://127.0.0.1:28257/events
ecapture tls --model keylog --keylogfile capture.keys --libssl /usr/lib/x86_64-linux-gnu/libssl.so.3
ecapture tls --model pcapng --pcapfile android.pcapng -i wlan0 --libssl /apex/com.android.conscrypt/lib64/libssl.so`,
	RunE: openSSLCommandFunc,
}

func init() {
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.OpensslPath, "libssl", "", "Path to the OpenSSL or BoringSSL shared library (searches standard library paths if omitted)")
	opensslCmd.PersistentFlags().StringVar(&globalConf.CGroupPath, "cgroup_path", "", tlsCgroupHelp)
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.CaptureMode, "model", "m", "text", tlsModeHelp)
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.TextSource, "text-source", handlers.TextSourcePcapng, tlsTextSourceHelp)
	bindDecryptFlags(opensslCmd, &opensslConfig.DecryptConfig)
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.KeylogFile, "keylogfile", "k", "", tlsKeylogFileHelp)
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.PcapFile, "pcapfile", "w", "", tlsPcapFileHelp)
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.Ifname, "ifname", "i", "", tlsIfnameHelp)
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.SslVersion, "ssl_version", "", `Override the detected library version (for example, "openssl 3.0.12" or "boringssl_a_14")`)
	opensslCmd.PersistentFlags().BoolVar(&globalConf.PerfReorder, "perf-reorder", false, perfReorderHelp)
	opensslCmd.PersistentFlags().UintVar(&globalConf.PerfReorderLagMs, "perf-reorder-lag-ms", 10, perfReorderLagHelp)
	rootCmd.AddCommand(opensslCmd)
}

// openSSLCommandFunc executes the "tls" command using the new probe architecture.
func openSSLCommandFunc(command *cobra.Command, args []string) error {
	if err := normalizeTLSOutputFlags(command, opensslConfig.CaptureMode, &opensslConfig.TextSource, &opensslConfig.KeylogFile, &opensslConfig.PcapFile); err != nil {
		return err
	}
	if opensslConfig.PcapFilter == "" && len(args) != 0 {
		opensslConfig.PcapFilter = strings.Join(args, " ")
	}

	// Run probe using the common entry point
	return runConfiguredProbe(factory.ProbeTypeOpenSSL, opensslConfig)
}
