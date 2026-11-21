//go:build !ecap_android
// +build !ecap_android

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
	gnutlsProbe "github.com/gojue/ecapture/v2/internal/probe/gnutls"
)

var gnutlsConfig = gnutlsProbe.NewConfig()

// gnutlsCmd represents the gnutls command.
var gnutlsCmd = &cobra.Command{
	Use:     "gnutls [flags] [pcap filter expression]",
	Aliases: []string{"gnu"},
	Short:   "Capture TLS traffic from applications that use GnuTLS",
	Long:    tlsCaptureHelp,
	Example: `ecapture gnutls --model text --text-source pcapng
ecapture gnutls --model text --text-source pcapng --gnutls /usr/lib/x86_64-linux-gnu/libgnutls.so.30
ecapture gnutls --model keylog --keylogfile capture.keys
ecapture gnutls --model pcapng --pcapfile capture.pcapng -i eth0 'tcp port 443'`,
	RunE: gnuTlsCommandFunc,
}

func init() {
	gnutlsCmd.PersistentFlags().StringVar(&gnutlsConfig.GnutlsPath, "gnutls", "", "Path to the GnuTLS shared library (searches standard library paths if omitted)")
	gnutlsCmd.PersistentFlags().StringVarP(&gnutlsConfig.CaptureMode, "model", "m", "text", tlsModeHelp)
	gnutlsCmd.PersistentFlags().StringVar(&gnutlsConfig.TextSource, "text-source", handlers.TextSourcePcapng, tlsTextSourceHelp)
	bindDecryptFlags(gnutlsCmd, &gnutlsConfig.DecryptConfig)
	gnutlsCmd.PersistentFlags().StringVarP(&gnutlsConfig.KeylogFile, "keylogfile", "k", "", tlsKeylogFileHelp)
	gnutlsCmd.PersistentFlags().StringVarP(&gnutlsConfig.PcapFile, "pcapfile", "w", "", tlsPcapFileHelp)
	gnutlsCmd.PersistentFlags().StringVarP(&gnutlsConfig.Ifname, "ifname", "i", "", tlsIfnameHelp)
	gnutlsCmd.PersistentFlags().StringVar(&gnutlsConfig.GnuVersion, "ssl_version", "", "Override the detected GnuTLS patch version (for example, 3.7.9)")
	gnutlsCmd.PersistentFlags().StringVar(&globalConf.CGroupPath, "cgroup_path", "", tlsCgroupHelp)
	rootCmd.AddCommand(gnutlsCmd)
}

// gnuTlsCommandFunc executes the "gnutls" command using the new probe architecture.
func gnuTlsCommandFunc(command *cobra.Command, args []string) error {
	if err := normalizeTLSOutputFlags(command, gnutlsConfig.CaptureMode, &gnutlsConfig.TextSource, &gnutlsConfig.KeylogFile, &gnutlsConfig.PcapFile); err != nil {
		return err
	}
	if gnutlsConfig.PcapFilter == "" && len(args) != 0 {
		gnutlsConfig.PcapFilter = strings.Join(args, " ")
	}

	// Run probe using the common entry point
	return runConfiguredProbe(factory.ProbeTypeGnuTLS, gnutlsConfig)
}
