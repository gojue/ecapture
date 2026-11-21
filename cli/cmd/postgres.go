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
	postgresProbe "github.com/gojue/ecapture/v2/internal/probe/postgres"
)

var postgresConfig = postgresProbe.NewConfig()

// postgres Cmd represents the postgres command
var postgresCmd = &cobra.Command{
	Use:     "postgres",
	Short:   "Capture SQL sent through PostgreSQL's simple query protocol",
	Long:    "Trace exec_simple_query in the server executable on PostgreSQL 10 and later.",
	Example: "ecapture postgres --postgres /usr/lib/postgresql/15/bin/postgres",
	RunE:    postgresCommandFunc,
}

func init() {
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.PostgresPath, "postgres", "m", "/usr/bin/postgres", "Path to the PostgreSQL server executable.")
	postgresCmd.PersistentFlags().StringVarP(&postgresConfig.FuncName, "funcname", "f", "", "Server function to trace (default exec_simple_query). Its first argument must be the SQL string.")
	postgresCmd.PersistentFlags().BoolVar(&globalConf.PerfReorder, "perf-reorder", false, perfReorderHelp)
	postgresCmd.PersistentFlags().UintVar(&globalConf.PerfReorderLagMs, "perf-reorder-lag-ms", 10, perfReorderLagHelp)
	rootCmd.AddCommand(postgresCmd)
}

// postgres CommandFunc executes the "psql" command using the new probe architecture.
func postgresCommandFunc(command *cobra.Command, args []string) error {
	// Run probe using the common entry point
	return runConfiguredProbe(factory.ProbeTypePostgres, postgresConfig)
}
