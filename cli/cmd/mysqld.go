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
	_ "github.com/gojue/ecapture/internal/probe/mysql"

	"github.com/gojue/ecapture/internal/factory"
	mysqlProbe "github.com/gojue/ecapture/internal/probe/mysql"
)

var mysqlConfig = mysqlProbe.NewConfig()

// mysqldCmd represents the mysqld command
var mysqldCmd = &cobra.Command{
	Use:   "mysqld",
	Short: "capture sql queries from mysqld 5.6/5.7/8.0 .",
	Long: ` only support mysqld 5.6/5.7/8.0 and mariadDB 10.5+.

other version coming soon`,
	RunE: mysqldCommandFunc,
}

func init() {
	mysqldCmd.PersistentFlags().StringVarP(&mysqlConfig.MysqlPath, "mysqld", "m", "/usr/sbin/mariadbd", "mysqld binary file path, use to hook")
	mysqldCmd.PersistentFlags().Uint64VarP(&mysqlConfig.Offset, "offset", "", 0, "0x710410")
	mysqldCmd.PersistentFlags().StringVarP(&mysqlConfig.FuncName, "funcname", "f", "", "function name to hook")
	rootCmd.AddCommand(mysqldCmd)
}

// mysqldCommandFunc executes the "mysqld" command using the new probe architecture.
func mysqldCommandFunc(command *cobra.Command, args []string) error {
	// Set global config to mysql-specific config
	mysqlConfig.SetPid(globalConf.Pid)
	mysqlConfig.SetUid(globalConf.Uid)
	mysqlConfig.SetDebug(globalConf.Debug)
	mysqlConfig.SetHex(globalConf.IsHex)
	mysqlConfig.SetBTF(globalConf.BtfMode)
	mysqlConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	mysqlConfig.SetTruncateSize(globalConf.TruncateSize)

	// Validate configuration
	if err := mysqlConfig.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Create probe via factory
	probe, err := factory.CreateProbe(factory.ProbeTypeMySQL)
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
	if err := probe.Initialize(ctx, mysqlConfig, dispatcher); err != nil {
		return fmt.Errorf("failed to initialize probe: %w", err)
	}

	// Start probe
	if err := probe.Start(ctx); err != nil {
		return fmt.Errorf("failed to start probe: %w", err)
	}

	fmt.Println("MySQL probe started successfully. Press Ctrl+C to stop.")

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nStopping MySQL probe...")

	// Stop probe
	if err := probe.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop probe: %w", err)
	}

	return nil
}
