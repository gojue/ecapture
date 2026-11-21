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
	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/v2/internal/factory"
	nsprProbe "github.com/gojue/ecapture/v2/internal/probe/nspr"
)

var nsprConfig = nsprProbe.NewConfig()

// nssCmd represents the nspr command
var nssCmd = &cobra.Command{
	Use:     "nspr",
	Aliases: []string{"nss"},
	Short:   "Capture data read and written through NSPR",
	Long:    "Trace PR_Read and PR_Write in the NSPR library to capture application data. This probe requires NSS 3.x.",
	Example: `ecapture nspr --pid 3423 --output capture.jsonl
ecapture nspr --nspr /usr/lib/x86_64-linux-gnu/libnspr4.so`,
	RunE: nssCommandFunc,
}

func init() {
	nssCmd.PersistentFlags().StringVar(&nsprConfig.NSPRPath, "nspr", "", "Path to the library that exports PR_Read and PR_Write. By default, search standard library directories for libnspr4.so.")
	nssCmd.PersistentFlags().StringVar(&globalConf.CGroupPath, "cgroup_path", "", "Unused by the NSPR probe. Use --pid or --uid to filter by process or user.")
	rootCmd.AddCommand(nssCmd)
}

// nssCommandFunc executes the "nspr" command using the new probe architecture.
func nssCommandFunc(command *cobra.Command, args []string) error {
	// Run probe using the common entry point
	return runConfiguredProbe(factory.ProbeTypeNSPR, nsprConfig)
}
