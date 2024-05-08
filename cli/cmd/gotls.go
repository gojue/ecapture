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
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/module"
	"strings"

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
ecapture gotls -m keylog -k /tmp/ecap_gotls_key.log --elfpath=/home/cfc4n/go_https_client -l save.log --pid=3423
ecapture gotls -m pcap --pcapfile=save_android.pcapng -i wlan0 --elfpath=/home/cfc4n/go_https_client tcp port 443
`,
	Run: goTLSCommandFunc,
}

func init() {
	gotlsCmd.PersistentFlags().StringVarP(&goc.Path, "elfpath", "e", "", "ELF path to binary built with Go toolchain.")
	gotlsCmd.PersistentFlags().StringVarP(&goc.PcapFile, "pcapfile", "w", "ecapture_gotls.pcapng", "write the  raw packets to file as pcapng format.")
	gotlsCmd.PersistentFlags().StringVarP(&goc.Model, "model", "m", "text", "capture model, such as : text, pcap/pcapng, key/keylog")
	gotlsCmd.PersistentFlags().StringVarP(&goc.KeylogFile, "keylogfile", "k", "ecapture_gotls_key.log", "The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.")
	gotlsCmd.PersistentFlags().StringVarP(&goc.Ifname, "ifname", "i", "", "(TC Classifier) Interface name on which the probe will be attached.")
	rootCmd.AddCommand(gotlsCmd)
}

// goTLSCommandFunc executes the "bash" command.
func goTLSCommandFunc(command *cobra.Command, args []string) {
	if goc.PcapFilter == "" && len(args) != 0 {
		goc.PcapFilter = strings.Join(args, " ")
	}

	runModule(module.ModuleNameGotls, goc)
}
