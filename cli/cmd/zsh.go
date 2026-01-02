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
	"github.com/spf13/cobra"

	// Import new probe packages to register them with factory
	_ "github.com/gojue/ecapture/internal/probe/zsh"

	"github.com/gojue/ecapture/internal/factory"
	zshProbe "github.com/gojue/ecapture/internal/probe/zsh"
)

var zshConfig = zshProbe.NewConfig()

// zshCmd represents the zsh command
var zshCmd = &cobra.Command{
	Use:   "zsh",
	Short: "capture zsh command",
	Long: `eCapture capture zsh commands for zsh security audit, 
Auto find the zsh of the current env as the capture target.`,
	RunE: zshCommandFunc,
}

func init() {
	zshCmd.PersistentFlags().StringVar(&zshConfig.Zshpath, "zsh", "", "$SHELL file path, eg: /bin/zsh , will automatically find it from $ENV default.")
	zshCmd.Flags().IntVarP(&zshConfig.ErrNo, "errnumber", "e", 128, "only show the command which exec reulst equals err number.")
	rootCmd.AddCommand(zshCmd)
}

// zshCommandFunc executes the "zsh" command using the new probe architecture.
func zshCommandFunc(command *cobra.Command, args []string) error {
	// Set global config to zsh-specific config
	zshConfig.SetPid(globalConf.Pid)
	zshConfig.SetUid(globalConf.Uid)
	zshConfig.SetDebug(globalConf.Debug)
	zshConfig.SetHex(globalConf.IsHex)
	zshConfig.SetBTF(globalConf.BtfMode)
	zshConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	zshConfig.SetTruncateSize(globalConf.TruncateSize)

	// Run probe using the common entry point
	return runProbe(factory.ProbeTypeZsh, zshConfig)
}
