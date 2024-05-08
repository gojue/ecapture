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

var bc = config.NewBashConfig()

// bashCmd represents the bash command
var bashCmd = &cobra.Command{
	Use:   "bash",
	Short: "capture bash command",
	Long: `eCapture capture bash commands for bash security audit, 
Auto find the bash of the current env as the capture target.`,
	Run: bashCommandFunc,
}

func init() {
	bashCmd.PersistentFlags().StringVar(&bc.Bashpath, "bash", "", "$SHELL file path, eg: /bin/bash , will automatically find it from $ENV default.")
	bashCmd.PersistentFlags().StringVar(&bc.Readline, "readlineso", "", "readline.so file path, will automatically find it from $BASH_PATH default.")
	bashCmd.Flags().IntVarP(&bc.ErrNo, "errnumber", "e", module.BashErrnoDefault, "only show the command which exec reulst equals err number.")
	rootCmd.AddCommand(bashCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// bashCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// bashCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// bashCommandFunc executes the "bash" command.
func bashCommandFunc(command *cobra.Command, args []string) {
	runModule(module.ModuleNameBash, bc)
}
