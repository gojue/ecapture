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
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/module"
	"github.com/spf13/cobra"
)

var nc = config.NewNsprConfig()

// gnutlsCmd represents the openssl command
var nssCmd = &cobra.Command{
	Use:     "nss",
	Aliases: []string{"nspr"},
	Short:   "capture nss/nspr encrypted text content without CA cert for nss/nspr libraries.",
	Long: `use eBPF uprobe/TC to capture process event data.
ecapture nss
ecapture nss --hex --pid=3423
ecapture nss -l save.log --pid=3423
ecapture nss --nspr=/lib/x86_64-linux-gnu/libnspr44.so
`,
	Run: nssCommandFunc,
}

func init() {
	//nssCmd.PersistentFlags().StringVar(&nc.Firefoxpath, "firefox", "", "firefox file path, default: /usr/lib/firefox/firefox. (Deprecated)")
	nssCmd.PersistentFlags().StringVar(&nc.Nsprpath, "nspr", "", "libnspr44.so file path, will automatically find it from curl default.")
	rootCmd.AddCommand(nssCmd)
}

// nssCommandFunc executes the "bash" command.
func nssCommandFunc(command *cobra.Command, args []string) {
	runModule(module.ModuleNameNspr, nc)
}
