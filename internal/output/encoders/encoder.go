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

package encoders

import (
	"github.com/gojue/ecapture/internal/domain"
)

// Encoder defines the interface for encoding events into different formats.
// This abstraction separates encoding logic from event processing and output destination.
type Encoder interface {
	// Encode converts an event into bytes according to the encoder's format
	Encode(event domain.Event) ([]byte, error)

	// Name returns the encoder name (e.g., "plain", "json", "protobuf")
	Name() string
}
