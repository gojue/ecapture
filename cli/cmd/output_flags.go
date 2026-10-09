// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func normalizeTLSOutputFlags(command *cobra.Command, mode string, keylogFile, pcapFile *string) error {
	eventFlag := command.Flag("eventaddr")
	if eventFlag == nil || !eventFlag.Changed {
		return nil
	}
	mode = strings.ToLower(mode)
	switch mode {
	case "key", "keylog":
		if flag := command.Flag("keylogfile"); flag != nil && flag.Changed {
			return fmt.Errorf("--eventaddr and --keylogfile cannot both select the primary keylog destination")
		}
		*keylogFile = ""
	case "pcap", "pcapng":
		if flag := command.Flag("pcapfile"); flag != nil && flag.Changed {
			return fmt.Errorf("--eventaddr and --pcapfile cannot both select the primary pcapng destination")
		}
		*pcapFile = ""
	}
	return nil
}
