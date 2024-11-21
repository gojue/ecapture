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

var dc = config.NewDashConfig()

// dashCmd represents the dash command
var dashCmd = &cobra.Command{
	Use:   "dash",
	Short: "capture dash command",
	Long: `eCapture capture dash commands for dash security audit, 
Auto find the dash of the current env as the capture target.`,
	Run: dashCommandFunc,
}

func init() {
	dashCmd.PersistentFlags().StringVar(&dc.Dashpath, "dash", "", "$SHELL file path, eg: /bin/dash , will automatically find it from $ENV default.")
	dashCmd.PersistentFlags().StringVar(&dc.Readline, "readlineso", "", "readline.so file path, will automatically find it from $BASH_PATH default.")
	dashCmd.Flags().IntVarP(&dc.ErrNo, "errnumber", "e", module.DashErrnoDefault, "only show the command which exec reulst equals err number.")
	rootCmd.AddCommand(dashCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dashCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dashCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// dashCommandFunc executes the "dash" command.
func dashCommandFunc(command *cobra.Command, args []string) {
	runModule(module.ModuleNameDash, dc)
}
