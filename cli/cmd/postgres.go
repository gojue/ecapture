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

var pgc = config.NewPostgresConfig()

// postgres Cmd represents the postgres command
var postgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "capture sql queries from postgres 10+.",
	Run:   postgresCommandFunc,
}

func init() {
	postgresCmd.PersistentFlags().StringVarP(&pgc.PostgresPath, "postgres", "m", "/usr/bin/postgres", "postgres binary file path, use to hook")
	postgresCmd.PersistentFlags().StringVarP(&pgc.FuncName, "funcname", "f", "", "function name to hook")
	rootCmd.AddCommand(postgresCmd)
}

// postgres CommandFunc executes the "psql" command.
func postgresCommandFunc(command *cobra.Command, args []string) {
	runModule(module.ModuleNamePostgres, pgc)
}
