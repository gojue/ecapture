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

	"github.com/gojue/ecapture/internal/factory"
	postgresProbe "github.com/gojue/ecapture/internal/probe/postgres"
)

var postgresConfig = postgresProbe.NewConfig()

// postgres Cmd represents the postgres command
var postgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "capture sql queries from postgres 10+.",
	RunE:  postgresCommandFunc,
}

func init() {
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.PostgresPath, "postgres", "m", "/usr/bin/postgres", "postgres binary file path, use to hook")
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.FuncName, "funcname", "f", "", "function name to hook")
	rootCmd.AddCommand(postgresCmd)
}

// postgres CommandFunc executes the "psql" command using the new probe architecture.
func postgresCommandFunc(command *cobra.Command, args []string) error {
	// Set global config to postgres-specific config
	postgresConfig.SetPid(globalConf.Pid)
	postgresConfig.SetUid(globalConf.Uid)
	postgresConfig.SetDebug(globalConf.Debug)
	postgresConfig.SetHex(globalConf.IsHex)
	postgresConfig.SetBTF(globalConf.BtfMode)
	postgresConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	postgresConfig.SetTruncateSize(globalConf.TruncateSize)

	// Run probe using the common entry point
	return runProbe(factory.ProbeTypePostgres, postgresConfig)
}
