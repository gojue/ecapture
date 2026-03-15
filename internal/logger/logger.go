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
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger to provide a consistent logging interface.
type Logger struct {
	*zerolog.Logger
}

// escapeCtrlChars encodes non-printable control characters as escape sequences,
// following the same convention as Linux strace when displaying string arguments.
// Actual newlines and tabs are preserved so log output remains human-readable;
// all other control characters (0x00-0x1F except \t/\n, plus DEL 0x7F) are
// replaced with named escapes (\a \b \f \r \v) or \xHH hex escapes.
func escapeCtrlChars(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\n', '\t':
			b.WriteRune(r) // preserve newline and tab for readability
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '\v':
			b.WriteString(`\v`)
		default:
			if r < 0x20 || r == 0x7F {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
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

	// When writing to stdout, encode control characters as escape sequences to prevent
	// terminal corruption (#931), following the same convention as Linux strace.
	if out == os.Stdout {
		consoleWriter.FormatMessage = func(i interface{}) string {
			if i == nil {
				return ""
			}
			msg, ok := i.(string)
			if !ok {
				msg = fmt.Sprint(i)
			}
			return escapeCtrlChars(msg)
		}
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

func (l *Logger) Write(p []byte) (n int, err error) {
	l.Logger.Info().Msg(string(p))
	return len(p), nil
}
