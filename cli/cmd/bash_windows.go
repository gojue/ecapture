//go:build windows
// +build windows

// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

	"github.com/gojue/ecapture/internal/factory"
	bashProbe "github.com/gojue/ecapture/internal/probe/bash"
)

var bashConfig = bashProbe.NewConfig()

// bashCmd represents the bash command
var bashCmd = &cobra.Command{
	Use:   "bash",
	Short: "capture shell commands on Windows (PowerShell, cmd, bash)",
	Long: `eCapture captures shell commands on Windows for security audit.
Supports PowerShell, cmd.exe, and bash (WSL/Git Bash).
Auto-detects available shells from common installation paths.`,
	RunE: bashCommandFunc,
}

func init() {
	bashCmd.PersistentFlags().StringVar(&bashConfig.Bashpath, "shell", "", "shell binary path, eg: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe. Auto-detects if not set.")
	bashCmd.PersistentFlags().StringVar(&bashConfig.ShellType, "shell-type", "", "shell type: powershell, cmd, or bash. Auto-detected from binary path if not set.")
	rootCmd.AddCommand(bashCmd)
}

// bashCommandFunc executes the "bash" command on Windows.
func bashCommandFunc(command *cobra.Command, args []string) error {
	// Set global config to bash-specific config
	bashConfig.SetPid(globalConf.Pid)
	bashConfig.SetUid(globalConf.Uid)
	bashConfig.SetDebug(globalConf.Debug)
	bashConfig.SetHex(globalConf.IsHex)
	bashConfig.SetBTF(globalConf.BtfMode)
	bashConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	bashConfig.SetTruncateSize(globalConf.TruncateSize)

	// Run probe using the common entry point
	return runProbe(factory.ProbeTypeBash, bashConfig)
}
