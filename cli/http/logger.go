// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package http

import (
	"strings"

	"github.com/rs/zerolog"
)

type ErrLogger struct {
	zerologger zerolog.Logger
}

func (el *ErrLogger) Write(p []byte) (n int, err error) {
	el.zerologger.Error().Msg(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

type InfoLogger struct {
	zerologger zerolog.Logger
}

func (el *InfoLogger) Write(p []byte) (n int, err error) {
	el.zerologger.Info().Msg(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

type DebugLogger struct {
	zerologger zerolog.Logger
}

func (el *DebugLogger) Write(p []byte) (n int, err error) {
	el.zerologger.Info().Msg(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
