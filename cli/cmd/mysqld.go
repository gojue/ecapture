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

var myc = config.NewMysqldConfig()

// mysqldCmd represents the mysqld command
var mysqldCmd = &cobra.Command{
	Use:   "mysqld",
	Short: "capture sql queries from mysqld 5.6/5.7/8.0 .",
	Long: ` only support mysqld 5.6/5.7/8.0 and mariadDB 10.5+.

other version coming soon`,
	Run: mysqldCommandFunc,
}

func init() {
	mysqldCmd.PersistentFlags().StringVarP(&myc.Mysqldpath, "mysqld", "m", "/usr/sbin/mariadbd", "mysqld binary file path, use to hook")
	mysqldCmd.PersistentFlags().Uint64VarP(&myc.Offset, "offset", "", 0, "0x710410")
	mysqldCmd.PersistentFlags().StringVarP(&myc.FuncName, "funcname", "f", "", "function name to hook")
	rootCmd.AddCommand(mysqldCmd)
}

// mysqldCommandFunc executes the "mysqld" command.
func mysqldCommandFunc(command *cobra.Command, args []string) {
	runModule(module.ModuleNameMysqld, myc)
}
