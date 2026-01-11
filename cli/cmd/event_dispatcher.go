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
	// Determine capture mode and register appropriate handlers
	if probeConfig == nil {
		return nil, fmt.Errorf("probe configuration cannot be nil")
	}

	// Create internal logger wrapper from zerolog
	log := logger.New(os.Stdout, probeConfig.GetDebug())

	// Create dispatcher
	dispatcher := events.NewDispatcher(log)

	useHex := probeConfig.GetHex()

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
	zlogger.Info().Str("eventAddr", eventAddr).Str("LoggerAddr", globalConf.LoggerAddr).Msg("Text output writer created")
	textHandler := handlers.NewTextHandler(textWriter, useHex)
	if err := dispatcher.Register(textHandler); err != nil {
		_ = textWriter.Close()
		return nil, fmt.Errorf("failed to register text handler: %w", err)
	}
	zlogger.Info().
		Str("mode", "text").
		Bool("hex", useHex).
		Str("output", textWriter.Name()).
		Msg("Text handler registered")
	return dispatcher, nil
}
