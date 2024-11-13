//go:build !androidgki
// +build !androidgki

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

	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/module"
	"github.com/spf13/cobra"
)

var gc = config.NewGnutlsConfig()

// gnutlsCmd represents the openssl command
var gnutlsCmd = &cobra.Command{
	Use:     "gnutls",
	Aliases: []string{"gnu"},
	Short:   "capture gnutls text content without CA cert for gnutls libraries.",
	Long: `use eBPF uprobe/TC to capture process event data.
ecapture gnutls
ecapture gnutls --hex --pid=3423
ecapture gnutls -l save.log --pid=3423
ecapture gnutls --gnutls=/lib/x86_64-linux-gnu/libgnutls.so
ecapture gnutls -m keylog -k ecapture_gnutls_key.log --ssl_version=3.7.9
ecapture gnutls -m pcap --pcapfile save.pcapng -i eth0 --gnutls=/lib/x86_64-linux-gnu/libgnutls.so tcp port 443
`,
	Run: gnuTlsCommandFunc,
}

func init() {
	//opensslCmd.PersistentFlags().StringVar(&gc.Curlpath, "wget", "", "wget file path, default: /usr/bin/wget. (Deprecated)")
	gnutlsCmd.PersistentFlags().StringVar(&gc.Gnutls, "gnutls", "", "libgnutls.so file path, will automatically find it from curl default.")
	gnutlsCmd.PersistentFlags().StringVarP(&gc.Model, "model", "m", "text", "capture model, such as : text, pcap/pcapng, key/keylog")
	gnutlsCmd.PersistentFlags().StringVarP(&gc.KeylogFile, "keylogfile", "k", "ecapture_gnutls_key.log", "The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.")
	gnutlsCmd.PersistentFlags().StringVarP(&gc.PcapFile, "pcapfile", "w", "save.pcapng", "write the raw packets to file as pcapng format.")
	gnutlsCmd.PersistentFlags().StringVarP(&gc.Ifname, "ifname", "i", "", "(TC Classifier) Interface name on which the probe will be attached.")
	gnutlsCmd.PersistentFlags().StringVar(&gc.SslVersion, "ssl_version", "", "GnuTLS version, e.g: --ssl_version=\"3.7.9\"")
	rootCmd.AddCommand(gnutlsCmd)
}

// gnuTlsCommandFunc executes the "bash" command.
func gnuTlsCommandFunc(command *cobra.Command, args []string) {
	if gc.PcapFilter == "" && len(args) != 0 {
		gc.PcapFilter = strings.Join(args, " ")
	}
	runModule(module.ModuleNameGnutls, gc)
}
