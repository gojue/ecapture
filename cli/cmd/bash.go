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
	bashProbe "github.com/gojue/ecapture/v2/internal/probe/bash"
)

var bashConfig = bashProbe.NewConfig()

// bashCmd represents the bash command
var bashCmd = &cobra.Command{
	Use:   "bash",
	Short: "Capture commands entered in interactive Bash sessions",
	Long:  "Read command lines through Readline and collect their exit statuses from Bash.",
	RunE:  bashCommandFunc,
}

func init() {
	bashCmd.PersistentFlags().StringVar(&bashConfig.Bashpath, "bash", "", "Path to the Bash executable. Defaults to $SHELL if it points to Bash, otherwise /bin/bash.")
	bashCmd.PersistentFlags().StringVar(&bashConfig.Readline, "readlineso", "", "Path to the Readline shared library used by Bash. Supply --bash with this option.")
	bashCmd.Flags().IntVarP(&bashConfig.ErrNo, "errnumber", "e", 128, "Omit command completions with this exit status. Changing this value can cause other statuses to appear as 128.")
	rootCmd.AddCommand(bashCmd)
}

// bashCommandFunc executes the "bash" command using the new probe architecture.
func bashCommandFunc(command *cobra.Command, args []string) error {
	// Run probe using the common entry point
	return runConfiguredProbe(factory.ProbeTypeBash, bashConfig)
}
