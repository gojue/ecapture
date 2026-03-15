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
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
)

// ProtobufEncoder encodes events as Protocol Buffers format.
// Note: This is a placeholder implementation. Full protobuf support requires
// defining .proto schemas for each event type and generating the corresponding code.
type ProtobufEncoder struct{}

// NewProtobufEncoder creates a new protobuf encoder.
func NewProtobufEncoder() *ProtobufEncoder {
	return &ProtobufEncoder{}
}

// Encode converts an event to protobuf bytes.
func (e *ProtobufEncoder) Encode(event domain.Event) ([]byte, error) {
	// TODO: Implement protobuf encoding when .proto schemas are defined
	// For now, return an error indicating this is not yet implemented
	return nil, fmt.Errorf("protobuf encoding not yet implemented - requires .proto schema definitions")
}

// Name returns the encoder name.
func (e *ProtobufEncoder) Name() string {
	return "protobuf"
}
