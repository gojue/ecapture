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
	"io"
	"net"
	"os"
	"strings"
)

const (
	loggerTypeStdout = 0
	loggerTypeFile   = 1
	loggerTypeTcp    = 2
)

// GlobalFlags are flags that defined globally
// and are inherited to all sub-commands.
type GlobalFlags struct {
	IsHex      bool
	Debug      bool
	Pid        uint64 // PID
	Uid        uint64 // UID
	LoggerAddr string // save file
	mapSizeKB  int    // ebpf map size per CPU
	addrType   uint8  // 0:stdout, 1:file, 2:tcp
	address    string
	writer     io.Writer
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

	conf.mapSizeKB, err = command.Flags().GetInt("mapsize")
	if err != nil {
		return
	}

	conf.LoggerAddr, err = command.Flags().GetString("logaddr")
	if err != nil {
		return
	}
	conf.addrType = loggerTypeStdout
	conf.writer = os.Stdout
	if conf.LoggerAddr != "" {
		if strings.Contains(conf.LoggerAddr, "tcp://") {
			conf.address = strings.Replace(conf.LoggerAddr, "tcp://", "", 1)
			conf.addrType = loggerTypeTcp
			conn, e := net.Dial("tcp", conf.address)
			if e != nil {
				return GlobalFlags{}, e
			}
			conf.writer = conn
		} else {
			conf.address = conf.LoggerAddr
			conf.addrType = loggerTypeFile
			f, e := os.Create(conf.address)
			if e != nil {
				return GlobalFlags{}, e
			}
			conf.writer = f
		}
	}
	return
}
