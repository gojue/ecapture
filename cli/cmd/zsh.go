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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	// Import new probe packages to register them with factory
	_ "github.com/gojue/ecapture/internal/probe/zsh"

	"github.com/gojue/ecapture/internal/factory"
	zshProbe "github.com/gojue/ecapture/internal/probe/zsh"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/module"
)

var zc = config.NewZshConfig()

// zshCmd represents the zsh command
var zshCmd = &cobra.Command{
	Use:   "zsh",
	Short: "capture zsh command",
	Long: `eCapture capture zsh commands for zsh security audit, 
Auto find the zsh of the current env as the capture target.`,
	RunE: zshCommandFunc,
}

func init() {
	zshCmd.PersistentFlags().StringVar(&zc.Zshpath, "zsh", "", "$SHELL file path, eg: /bin/zsh , will automatically find it from $ENV default.")
	zshCmd.Flags().IntVarP(&zc.ErrNo, "errnumber", "e", module.ZshErrnoDefault, "only show the command which exec reulst equals err number.")
	rootCmd.AddCommand(zshCmd)
}

// zshCommandFunc executes the "zsh" command using the new probe architecture.
func zshCommandFunc(command *cobra.Command, args []string) error {
	// Check if we should use new architecture (check environment variable)
	if os.Getenv("ECAPTURE_USE_NEW_ARCH") != "1" {
		// Fall back to old architecture
		return runModule(module.ModuleNameZsh, zc)
	}

	// Create new architecture config from old config
	newConfig := zshProbe.NewConfig()
	newConfig.SetPid(globalConf.Pid)
	newConfig.SetUid(globalConf.Uid)
	newConfig.SetDebug(globalConf.Debug)
	newConfig.SetHex(globalConf.IsHex)
	newConfig.SetBTF(globalConf.BtfMode)
	newConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	newConfig.SetTruncateSize(globalConf.TruncateSize)

	// Set zsh-specific config
	newConfig.Zshpath = zc.Zshpath
	newConfig.ErrNo = zc.ErrNo

	// Validate configuration
	if err := newConfig.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Create probe via factory
	probe, err := factory.CreateProbe(factory.ProbeTypeZsh)
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
	if err := probe.Initialize(ctx, newConfig, dispatcher); err != nil {
		return fmt.Errorf("failed to initialize probe: %w", err)
	}

	// Start probe
	if err := probe.Start(ctx); err != nil {
		return fmt.Errorf("failed to start probe: %w", err)
	}

	fmt.Println("Zsh probe started successfully. Press Ctrl+C to stop.")

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nStopping zsh probe...")

	// Stop probe
	if err := probe.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop probe: %w", err)
	}

	return nil
}
