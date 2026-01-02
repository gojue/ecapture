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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	// Import new probe packages to register them with factory
	_ "github.com/gojue/ecapture/internal/probe/bash"

	"github.com/gojue/ecapture/internal/factory"
	bashProbe "github.com/gojue/ecapture/internal/probe/bash"
)

var bashConfig = bashProbe.NewConfig()

// bashCmd represents the bash command
var bashCmd = &cobra.Command{
	Use:   "bash",
	Short: "capture bash command",
	Long: `eCapture capture bash commands for bash security audit, 
Auto find the bash of the current env as the capture target.`,
	RunE: bashCommandFunc,
}

func init() {
	bashCmd.PersistentFlags().StringVar(&bashConfig.Bashpath, "bash", "", "$SHELL file path, eg: /bin/bash , will automatically find it from $ENV default.")
	bashCmd.PersistentFlags().StringVar(&bashConfig.Readline, "readlineso", "", "readline.so file path, will automatically find it from $BASH_PATH default.")
	bashCmd.Flags().IntVarP(&bashConfig.ErrNo, "errnumber", "e", 128, "only show the command which exec reulst equals err number.")
	rootCmd.AddCommand(bashCmd)
}

// bashCommandFunc executes the "bash" command using the new probe architecture.
func bashCommandFunc(command *cobra.Command, args []string) error {
	// Set global config to bash-specific config
	bashConfig.SetPid(globalConf.Pid)
	bashConfig.SetUid(globalConf.Uid)
	bashConfig.SetDebug(globalConf.Debug)
	bashConfig.SetHex(globalConf.IsHex)
	bashConfig.SetBTF(globalConf.BtfMode)
	bashConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	bashConfig.SetTruncateSize(globalConf.TruncateSize)

	// Validate configuration
	if err := bashConfig.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Create probe via factory
	probe, err := factory.CreateProbe(factory.ProbeTypeBash)
	if err != nil {
		return fmt.Errorf("failed to create probe: %w", err)
	}
	defer probe.Close()

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create event dispatcher
	dispatcher, err := newEventDispatcher(globalConf.IsHex)
	if err != nil {
		return fmt.Errorf("failed to create event dispatcher: %w", err)
	}
	defer dispatcher.Close()

	// Initialize probe
	if err := probe.Initialize(ctx, bashConfig, dispatcher); err != nil {
		return fmt.Errorf("failed to initialize probe: %w", err)
	}

	// Start probe
	if err := probe.Start(ctx); err != nil {
		return fmt.Errorf("failed to start probe: %w", err)
	}

	fmt.Println("Bash probe started successfully. Press Ctrl+C to stop.")

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nStopping bash probe...")

	// Stop probe
	if err := probe.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop probe: %w", err)
	}

	return nil
}
