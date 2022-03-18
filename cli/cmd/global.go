/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// GlobalFlags are flags that defined globally
// and are inherited to all sub-commands.
type GlobalFlags struct {
	IsHex bool
	Debug bool
	Pid   uint64 // PID
}

func getGlobalConf(command *cobra.Command) (conf GlobalFlags, err error) {
	conf.Pid, err = command.Flags().GetUint64("pid")
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
	return
}
