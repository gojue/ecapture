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

package handlers

import (
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/output/writers"
)

// MasterSecretInfoHandler handles master secret events by printing summary information to stdout.
// This handler is used in keylog mode to show users that master secrets are being captured,
// without writing the actual secrets to stdout (secrets are written to the keylog file).
type MasterSecretInfoHandler struct {
	writer writers.OutputWriter
}

// NewMasterSecretInfoHandler creates a new handler that prints master secret event summaries.
func NewMasterSecretInfoHandler(writer writers.OutputWriter) *MasterSecretInfoHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
	}
	return &MasterSecretInfoHandler{
		writer: writer,
	}
}

// Handle processes a master secret event and prints summary information.
func (h *MasterSecretInfoHandler) Handle(event domain.Event) error {
	if event == nil {
		return nil
	}

	// Check if this is a master secret event by using the String() method
	// MasterSecretEvent implements String() to return: "TLS Version: ..., ClientRandom: ..."
	output := fmt.Sprintf("%s\n", event.String())

	// Write to output
	_, err := h.writer.Write([]byte(output))
	return err
}

// Name returns the handler's identifier.
func (h *MasterSecretInfoHandler) Name() string {
	return "mastersecret_info"
}

// Close implements the handler close interface.
func (h *MasterSecretInfoHandler) Close() error {
	if h.writer != nil {
		return h.writer.Close()
	}
	return nil
}
