//go:build windows
// +build windows

// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

	"github.com/gojue/ecapture/internal/factory"
	opensslProbe "github.com/gojue/ecapture/internal/probe/openssl"
)

var opensslConfig = opensslProbe.NewConfig()

// opensslCmd represents the openssl command
var opensslCmd = &cobra.Command{
	Use:     "tls",
	Aliases: []string{"openssl"},
	Short:   "Used to capture TLS/SSL text content on Windows. (Supports Schannel ETW and OpenSSL DLL hooking).",
	Long: `Captures TLS/SSL plaintext content on Windows using Schannel ETW provider or OpenSSL DLL hooking.

ecapture tls -m [text|keylog|pcap] [flags] [pcap filter expression (for pcap mode)]
ecapture tls --schannel -m text
ecapture tls --libssl="C:\Program Files\OpenSSL-Win64\bin\libssl-3-x64.dll" -m keylog -k save_key.log
ecapture tls -m pcap -i Ethernet -w save.pcapng host 192.168.1.1 and tcp port 443
`,
	Example: "ecapture tls --schannel -m text",
	RunE:    openSSLCommandFunc,
}

func init() {
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.OpensslPath, "libssl", "", "OpenSSL DLL file path (e.g. libssl-3-x64.dll). If not set, auto-detects common paths or falls back to Schannel ETW.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.CaptureMode, "model", "m", "text", "capture model, such as : text, pcap/pcapng, key/keylog")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.KeylogFile, "keylogfile", "k", "ecapture_openssl_key.log", "The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.PcapFile, "pcapfile", "w", "save.pcapng", "write the raw packets to file as pcapng format.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.Ifname, "ifname", "i", "", "Network interface name on which the probe will be attached (for pcap mode).")
	opensslCmd.PersistentFlags().BoolVar(&opensslConfig.UseSchannel, "schannel", true, "use Schannel ETW provider for TLS capture (default true)")
	rootCmd.AddCommand(opensslCmd)
}

// openSSLCommandFunc executes the "tls" command on Windows.
func openSSLCommandFunc(command *cobra.Command, args []string) error {
	if opensslConfig.PcapFilter == "" && len(args) != 0 {
		opensslConfig.PcapFilter = strings.Join(args, " ")
	}

	// Set global config to openssl-specific config
	opensslConfig.SetPid(globalConf.Pid)
	opensslConfig.SetUid(globalConf.Uid)
	opensslConfig.SetDebug(globalConf.Debug)
	opensslConfig.SetHex(globalConf.IsHex)
	opensslConfig.SetBTF(globalConf.BtfMode)
	opensslConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	opensslConfig.SetTruncateSize(globalConf.TruncateSize)

	// Run probe using the common entry point
	return runProbe(factory.ProbeTypeOpenSSL, opensslConfig)
}
