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
	"github.com/spf13/cobra"
	"strings"
)

var oc = config.NewOpensslConfig()

// opensslCmd represents the openssl command
var opensslCmd = &cobra.Command{
	Use:     "tls",
	Aliases: []string{"openssl"},
	Short:   "Used to capture TLS/SSL text content without the need for a CA certificate. (Supports OpenSSL 1.0.x/1.1.x/3.x or newer).",
	Long: `Uses eBPF uprobe/TC to capture process event data and network data. Also supports the pcap-NG format.

ecapture tls -m [text|keylog|pcap] [flags] [pcap filter expression (for pcap mode)]
ecapture tls -m pcap -i wlan0 -w save.pcapng host 192.168.1.1 and tcp port 443
ecapture tls -l save.log --pid=3423
ecapture tls --libssl=/lib/x86_64-linux-gnu/libssl.so.1.1
ecapture tls -m keylog --pcapfile save_3_0_5.pcapng --ssl_version="openssl 3.0.5" --libssl=/lib/x86_64-linux-gnu/libssl.so.3
ecapture tls -m pcap --pcapfile save_android.pcapng -i wlan0 --libssl=/apex/com.android.conscrypt/lib64/libssl.so --ssl_version="boringssl 1.1.1" tcp port 443

Docker usage:
docker pull gojue/ecapture
docker run --rm --privileged=true --net=host -v /etc:/etc -v /usr:/usr -v ${PWD}:/output gojue/ecapture tls -m pcap -i wlp3s0 --pcapfile=/output/ecapture.pcapng tcp port 443
`,
	Example: "ecapture tls -m pcap -i wlan0 -w save.pcapng host 192.168.1.1 and tcp port 443",
	Run:     openSSLCommandFunc,
}

func init() {
	// opensslCmd.PersistentFlags().StringVar(&oc.Curlpath, "curl", "", "curl or wget file path, use to dectet openssl.so path, default:/usr/bin/curl. (Deprecated)")
	opensslCmd.PersistentFlags().StringVar(&oc.Openssl, "libssl", "", "libssl.so file path, will automatically find it from curl default.")
	opensslCmd.PersistentFlags().StringVar(&oc.CGroupPath, "cgroup_path", "/sys/fs/cgroup", "cgroup path, default: /sys/fs/cgroup.")
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
	runModule(module.ModuleNameOpenssl, oc)
}
