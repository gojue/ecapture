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
	"encoding/json"
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
)

// JsonEncoder encodes events as JSON format.
type JsonEncoder struct {
	prettyPrint bool
}

// NewJsonEncoder creates a new JSON encoder.
func NewJsonEncoder(prettyPrint bool) *JsonEncoder {
	return &JsonEncoder{
		prettyPrint: prettyPrint,
	}
}

// Encode converts an event to JSON bytes.
func (e *JsonEncoder) Encode(event domain.Event) ([]byte, error) {
	var data []byte
	var err error

	if e.prettyPrint {
		data, err = json.MarshalIndent(event, "", "  ")
	} else {
		data, err = json.Marshal(event)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encode event as JSON: %w", err)
	}

	// Append newline for better readability
	data = append(data, '\n')
	return data, nil
}

// Name returns the encoder name.
func (e *JsonEncoder) Name() string {
	if e.prettyPrint {
		return "json-pretty"
	}
	return "json"
}
