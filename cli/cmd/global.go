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
)

// GlobalFlags are flags that defined globally
// and are inherited to all sub-commands.
type GlobalFlags struct {
	IsHex      bool
	Debug      bool
	Pid        uint64 // PID
	Uid        uint64 // UID
	NoSearch   bool   // No lib search
	loggerFile string // save file
}

func getGlobalConf(command *cobra.Command) (conf GlobalFlags, err error) {
	conf.Pid, err = command.Flags().GetUint64("pid")
	if err != nil {
		return
	}

	conf.Uid, err = command.Flags().GetUint64("uid")
	if err != nil {
		return
	}

	conf.Debug, err = command.Flags().GetBool("debug")
	if err != nil {
		return
	}

	conf.IsHex, err = command.Flags().GetBool("hex")
	if err != nil {
		return
	}

	conf.NoSearch, err = command.Flags().GetBool("nosearch")
	if err != nil {
		return
	}

	conf.loggerFile, err = command.Flags().GetString("log-file")
	if err != nil {
		return
	}
	return
}
