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

var zc = config.NewZshConfig()

// zshCmd represents the zsh command
var zshCmd = &cobra.Command{
	Use:   "zsh",
	Short: "capture zsh command",
	Long: `eCapture capture zsh commands for zsh security audit, 
Auto find the zsh of the current env as the capture target.`,
	Run: zshCommandFunc,
}

func init() {
	zshCmd.PersistentFlags().StringVar(&zc.Zshpath, "zsh", "", "$SHELL file path, eg: /bin/zsh , will automatically find it from $ENV default.")
	zshCmd.Flags().IntVarP(&zc.ErrNo, "errnumber", "e", module.ZshErrnoDefault, "only show the command which exec reulst equals err number.")
	rootCmd.AddCommand(zshCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all suzcommands, e.g.:
	// zshCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// zshCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// zshCommandFunc executes the "zsh" command.
func zshCommandFunc(command *cobra.Command, args []string) {
	runModule(module.ModuleNameZsh, zc)
}
