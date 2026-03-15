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

package writers

import (
	"io"
)

// OutputWriter defines the interface for writing output to various destinations.
// This abstraction separates output destination logic from event processing and encoding.
type OutputWriter interface {
	io.Writer
	io.Closer

	// Name returns a human-readable name for this writer (e.g., "stdout", "file:/tmp/log", "tcp://127.0.0.1:8080")
	Name() string

	// Flush ensures all buffered data is written to the destination
	Flush() error
}
