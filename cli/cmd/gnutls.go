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
`,
	Run: gnuTlsCommandFunc,
}

func init() {
	//opensslCmd.PersistentFlags().StringVar(&gc.Curlpath, "wget", "", "wget file path, default: /usr/bin/wget. (Deprecated)")
	gnutlsCmd.PersistentFlags().StringVar(&gc.Gnutls, "gnutls", "", "libgnutls.so file path, will automatically find it from curl default.")
	rootCmd.AddCommand(gnutlsCmd)
}

// gnuTlsCommandFunc executes the "bash" command.
func gnuTlsCommandFunc(command *cobra.Command, args []string) {
	runModule(module.ModuleNameGnutls, gc)
}
