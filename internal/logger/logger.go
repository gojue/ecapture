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

package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger to provide a consistent logging interface.
type Logger struct {
	*zerolog.Logger
}

// New creates a new Logger instance.
func New(out io.Writer, debug bool) *Logger {
	if out == nil {
		out = os.Stdout
	}

	consoleWriter := zerolog.ConsoleWriter{
		Out:        out,
		TimeFormat: time.RFC3339,
	}

	level := zerolog.InfoLevel
	if debug {
		level = zerolog.DebugLevel
	}

	zlog := zerolog.New(consoleWriter).
		Level(level).
		With().
		Timestamp().
		Logger()

	return &Logger{&zlog}
}

// WithComponent creates a child logger with a component field.
func (l *Logger) WithComponent(component string) *Logger {
	child := l.Logger.With().Str("component", component).Logger()
	return &Logger{&child}
}

// WithProbe creates a child logger with a probe field.
func (l *Logger) WithProbe(probe string) *Logger {
	child := l.Logger.With().Str("probe", probe).Logger()
	return &Logger{&child}
}

// WithPid creates a child logger with a pid field.
func (l *Logger) WithPid(pid uint64) *Logger {
	child := l.Logger.With().Uint64("pid", pid).Logger()
	return &Logger{&child}
}
