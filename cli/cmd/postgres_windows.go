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
	postgresProbe "github.com/gojue/ecapture/internal/probe/postgres"
)

var postgresConfig = postgresProbe.NewConfig()

// postgresCmd represents the postgres command on Windows.
var postgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "capture SQL queries from PostgreSQL client DLLs on Windows.",
	Long: `Captures SQL queries issued through libpq.dll on Windows by hooking functions
such as PQexec.

ecapture postgres --postgres "C:\Program Files\PostgreSQL\15\bin\libpq.dll"
ecapture postgres --funcname PQexec -p 1234`,
	RunE: postgresCommandFunc,
}

func init() {
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.PostgresPath, "postgres", "m", "", "PostgreSQL libpq.dll path. Auto-detected if not set.")
	postgresCmd.PersistentFlags().Uint64VarP(&postgresConfig.Offset, "offset", "", 0, "function offset inside the DLL")
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.FuncName, "funcname", "f", "PQexec", "function name to hook")
	rootCmd.AddCommand(postgresCmd)
}

// postgresCommandFunc executes the "postgres" command on Windows.
func postgresCommandFunc(command *cobra.Command, args []string) error {
	postgresConfig.SetPid(globalConf.Pid)
	postgresConfig.SetUid(globalConf.Uid)
	postgresConfig.SetDebug(globalConf.Debug)
	postgresConfig.SetHex(globalConf.IsHex)
	postgresConfig.SetBTF(globalConf.BtfMode)
	postgresConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	postgresConfig.SetTruncateSize(globalConf.TruncateSize)

	return runProbe(factory.ProbeTypePostgres, postgresConfig)
}
