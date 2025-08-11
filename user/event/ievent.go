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

package event

import (
	"github.com/rs/zerolog"
	"os"
	"time"
)

type Type uint8

const (
	// TypeOutput upload to server or write to logfile.
	TypeOutput Type = iota

	// TypeModuleData set as module cache data
	TypeModuleData

	// TypeEventProcessor display by event_processor.
	TypeEventProcessor
)

const SocketLifecycleUUIDPrefix = "sock:"

type IEventStruct interface {
	Decode(payload []byte) (err error)
	Payload() []byte
	PayloadLen() int
	String() string
	StringHex() string
	Clone() IEventStruct
	EventType() Type
	GetUUID() string
	Base() Base
}

// CollectorWriter is a custom writer that uses zerolog for event logging.
type CollectorWriter struct {
	logger *zerolog.Logger
}

func (e CollectorWriter) Write(p []byte) (n int, err error) {
	return e.logger.Write(p)
}

func NewCollectorWriter(logger *zerolog.Logger) CollectorWriter {
	if logger == nil {
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		lg := zerolog.New(consoleWriter).With().Timestamp().Logger()
		logger = &lg
	}
	return CollectorWriter{logger: logger}
}
