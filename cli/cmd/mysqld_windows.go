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
	mysqlProbe "github.com/gojue/ecapture/internal/probe/mysql"
)

var mysqlConfig = mysqlProbe.NewConfig()

// mysqldCmd represents the mysqld command on Windows.
var mysqldCmd = &cobra.Command{
	Use:   "mysqld",
	Short: "capture SQL queries from MySQL/MariaDB client DLLs on Windows.",
	Long: `Captures SQL queries issued through libmysql.dll / libmariadb.dll on Windows
by hooking functions such as mysql_real_query.

ecapture mysqld --mysqld "C:\Program Files\MySQL\MySQL Server 8.0\bin\libmysql.dll"
ecapture mysqld --funcname mysql_real_query -p 1234`,
	RunE: mysqldCommandFunc,
}

func init() {
	mysqldCmd.PersistentFlags().StringVarP(&mysqlConfig.MysqlPath, "mysqld", "m", "", "MySQL/MariaDB DLL path (e.g. libmysql.dll). Auto-detected if not set.")
	mysqldCmd.PersistentFlags().Uint64VarP(&mysqlConfig.Offset, "offset", "", 0, "function offset inside the DLL")
	mysqldCmd.PersistentFlags().StringVarP(&mysqlConfig.FuncName, "funcname", "f", "mysql_real_query", "function name to hook")
	rootCmd.AddCommand(mysqldCmd)
}

// mysqldCommandFunc executes the "mysqld" command on Windows.
func mysqldCommandFunc(command *cobra.Command, args []string) error {
	mysqlConfig.SetPid(globalConf.Pid)
	mysqlConfig.SetUid(globalConf.Uid)
	mysqlConfig.SetDebug(globalConf.Debug)
	mysqlConfig.SetHex(globalConf.IsHex)
	mysqlConfig.SetBTF(globalConf.BtfMode)
	mysqlConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	mysqlConfig.SetTruncateSize(globalConf.TruncateSize)

	return runProbe(factory.ProbeTypeMySQL, mysqlConfig)
}
