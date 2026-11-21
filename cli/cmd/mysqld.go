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
	mysqlProbe "github.com/gojue/ecapture/v2/internal/probe/mysql"
)

var mysqlConfig = mysqlProbe.NewConfig()

// mysqldCmd represents the mysqld command
var mysqldCmd = &cobra.Command{
	Use:   "mysqld",
	Short: "Capture SQL queries from MySQL or MariaDB",
	Long: `Capture SQL sent with COM_QUERY on MySQL 5.6, 5.7, and 8.0 or MariaDB 10.5 and later.
By default, eCapture detects the dispatch_command symbol and its calling convention.
Setting --funcname or --offset selects the MySQL 5.6/MariaDB calling convention.`,
	Example: "ecapture mysqld --mysqld /usr/sbin/mysqld",
	RunE:    mysqldCommandFunc,
}

func init() {
	mysqldCmd.PersistentFlags().StringVarP(&mysqlConfig.MysqlPath, "mysqld", "m", "/usr/sbin/mariadbd", "Path to the mysqld or mariadbd server executable.")
	mysqldCmd.PersistentFlags().Uint64VarP(&mysqlConfig.Offset, "offset", "", 0, "File offset of dispatch_command in the server executable, in decimal or hexadecimal (0x...).")
	mysqldCmd.PersistentFlags().StringVarP(&mysqlConfig.FuncName, "funcname", "f", "", "Exact ELF symbol name for dispatch_command, including any C++ name mangling.")
	mysqldCmd.PersistentFlags().BoolVar(&globalConf.PerfReorder, "perf-reorder", false, perfReorderHelp)
	mysqldCmd.PersistentFlags().UintVar(&globalConf.PerfReorderLagMs, "perf-reorder-lag-ms", 10, perfReorderLagHelp)
	rootCmd.AddCommand(mysqldCmd)
}

// mysqldCommandFunc executes the "mysqld" command using the new probe architecture.
func mysqldCommandFunc(command *cobra.Command, args []string) error {
	// Run probe using the common entry point
	return runConfiguredProbe(factory.ProbeTypeMySQL, mysqlConfig)
}
