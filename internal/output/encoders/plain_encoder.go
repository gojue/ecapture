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

// PlainEncoder encodes events as plain text using their String() method.
// This is the default encoder that preserves the original text format.
type PlainEncoder struct {
	useHex bool
}

// NewPlainEncoder creates a new plain text encoder.
func NewPlainEncoder(useHex bool) *PlainEncoder {
	return &PlainEncoder{
		useHex: useHex,
	}
}

// Encode converts an event to plain text bytes.
func (e *PlainEncoder) Encode(event domain.Event) ([]byte, error) {
	if e.useHex {
		return []byte(event.StringHex()), nil
	}
	return []byte(event.String()), nil
}

// Name returns the encoder name.
func (e *PlainEncoder) Name() string {
	if e.useHex {
		return "plain-hex"
	}
	return "plain"
}
