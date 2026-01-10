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
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/events"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/output/writers"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// newEventDispatcherWithConfig creates an event dispatcher with config-based handlers.
// All capture modes (text, keylog, pcap) use handlers from internal/probe/base/handlers package.
func newEventDispatcherWithConfig(zlogger *zerolog.Logger, probeConfig domain.Configuration) (domain.EventDispatcher, error) {
	// Create internal logger wrapper from zerolog
	log := logger.New(os.Stdout, false)

	// Create dispatcher
	dispatcher := events.NewDispatcher(log)

	// Determine capture mode and register appropriate handlers
	if probeConfig == nil {
		return dispatcher, fmt.Errorf("probe configuration cannot be nil")
	}

	// Type assert to check if this is a config with capture mode support
	type captureConfig interface {
		GetCaptureMode() string
		GetPcapFile() string
		GetKeylogFile() string
		GetHex() bool
	}

	cfg, ok := probeConfig.(captureConfig)
	if !ok {
		// Some probes (like bash, zsh) don't have capture mode
		// Register a default text handler for them
		zlogger.Debug().Msg("Probe does not support capture mode, registering default text handler")

		// Determine event output address (eventaddr or fallback to logaddr)
		eventAddr := globalConf.EventCollectorAddr
		if eventAddr == "" {
			eventAddr = globalConf.LoggerAddr
		}

		// Create writer factory for creating output writers
		writerFactory := writers.NewWriterFactory()

		// Configure rotation for file writers (from --eventroratesize and --eventroratetime flags)
		var rotateConfig *writers.RotateConfig
		if rorateSize > 0 || rorateTime > 0 {
			rotateConfig = &writers.RotateConfig{
				EnableRotate: true,
				MaxSizeMB:    int(rorateSize),
				MaxInterval:  time.Duration(rorateTime) * time.Second,
			}
		}

		// Create output writer based on eventAddr (or stdout if empty)
		var textWriter writers.OutputWriter
		var err error

		if eventAddr == "" || eventAddr == "stdout" {
			textWriter = writers.NewStdoutWriter()
		} else {
			textWriter, err = writerFactory.CreateWriter(eventAddr, rotateConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create text output writer: %w", err)
			}
		}

		// Register text handler with default settings (no hex mode)
		textHandler := handlers.NewTextHandler(textWriter, nil, false)
		if err := dispatcher.Register(textHandler); err != nil {
			_ = textWriter.Close()
			return nil, fmt.Errorf("failed to register text handler: %w", err)
		}

		zlogger.Info().
			Str("mode", "text").
			Str("output", textWriter.Name()).
			Msg("Default text handler registered for probe without capture mode support")

		return dispatcher, nil
	}

	captureMode := cfg.GetCaptureMode()
	useHex := cfg.GetHex()

	// Determine event output address (eventaddr or fallback to logaddr)
	eventAddr := globalConf.EventCollectorAddr
	if eventAddr == "" {
		eventAddr = globalConf.LoggerAddr
	}

	// Create writer factory for creating output writers
	writerFactory := writers.NewWriterFactory()

	// Configure rotation for file writers (from --eventroratesize and --eventroratetime flags)
	var rotateConfig *writers.RotateConfig
	if rorateSize > 0 || rorateTime > 0 {
		rotateConfig = &writers.RotateConfig{
			EnableRotate: true,
			MaxSizeMB:    int(rorateSize),
			MaxInterval:  time.Duration(rorateTime) * time.Second,
		}
	}

	switch captureMode {
	case handlers.ModeKeylog, handlers.ModeKey:
		// Keylog mode: use KeylogHandler with keylog file
		keylogFile := cfg.GetKeylogFile()
		if keylogFile == "" {
			return nil, fmt.Errorf("keylog mode requires keylog file path")
		}

		// Create file writer for keylog
		keylogWriter, err := writerFactory.CreateWriter(keylogFile, rotateConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create keylog writer: %w", err)
		}

		keylogHandler := handlers.NewKeylogHandler(keylogWriter)
		if err := dispatcher.Register(keylogHandler); err != nil {
			_ = keylogWriter.Close()
			return nil, fmt.Errorf("failed to register keylog handler: %w", err)
		}
		zlogger.Info().Str("keylog_file", keylogFile).Msg("Keylog handler registered")

		// Also register MasterSecretInfoHandler to print event info to stdout
		// This shows users that secrets are being captured
		infoWriter := writers.NewStdoutWriter()
		infoHandler := handlers.NewMasterSecretInfoHandler(infoWriter)
		if err := dispatcher.Register(infoHandler); err != nil {
			return nil, fmt.Errorf("failed to register master secret info handler: %w", err)
		}

	case handlers.ModePcap, handlers.ModePcapng:
		// Pcap mode: use PcapHandler with pcap file
		pcapFile := cfg.GetPcapFile()
		if pcapFile == "" {
			return nil, fmt.Errorf("pcap mode requires pcap file path")
		}

		// Create file writer for pcap (use O_TRUNC to overwrite existing file)
		// Note: pcap files should not use rotation
		pcapWriter, err := writers.NewFileWriter(writers.FileWriterConfig{
			Path:       pcapFile,
			BufferSize: 65536, // 64KB buffer for better pcap write performance
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create pcap writer: %w", err)
		}

		pcapHandler, err := handlers.NewPcapHandler(pcapWriter)
		if err != nil {
			_ = pcapWriter.Close()
			return nil, fmt.Errorf("failed to create pcap handler: %w", err)
		}

		if err := dispatcher.Register(pcapHandler); err != nil {
			_ = pcapHandler.Close()
			_ = pcapWriter.Close()
			return nil, fmt.Errorf("failed to register pcap handler: %w", err)
		}
		zlogger.Info().Str("pcap_file", pcapFile).Msg("Pcap handler registered")

	default:
		// Text mode: use TextHandler with configured output destination
		// Create output writer based on eventAddr (or stdout if empty)
		var textWriter writers.OutputWriter
		var err error

		if eventAddr == "" || eventAddr == "stdout" {
			textWriter = writers.NewStdoutWriter()
		} else {
			textWriter, err = writerFactory.CreateWriter(eventAddr, rotateConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create text output writer: %w", err)
			}
		}

		textHandler := handlers.NewTextHandler(textWriter, nil, useHex)
		if err := dispatcher.Register(textHandler); err != nil {
			_ = textWriter.Close()
			return nil, fmt.Errorf("failed to register text handler: %w", err)
		}
		zlogger.Info().
			Str("mode", "text").
			Bool("hex", useHex).
			Str("output", textWriter.Name()).
			Msg("Text handler registered")
	}

	return dispatcher, nil
}
