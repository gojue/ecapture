// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package config

import (
	"fmt"

	"github.com/gojue/ecapture_decryptor/types"
)

// DecryptConfig contains the opt-in parsing settings shared by TLS probes.
// Its zero value retains complete HTTP/WebSocket message output.
type DecryptConfig struct {
	TextRaw            bool   `json:"text_raw"`
	TextProtocol       string `json:"text_protocol"`
	TextHTTPEvents     bool   `json:"text_http_events"`
	TextMaxDecodedBody int64  `json:"text_max_decoded_body"`
	TextTLSUpgrade     string `json:"text_tls_upgrade"`
	TextUDPProtocol    string `json:"text_udp_protocol"`
}

func (c DecryptConfig) DecryptOptions() types.DecryptOptions {
	return types.DecryptOptions{
		RawChunks: c.TextRaw, ApplicationProtocol: c.TextProtocol,
		HTTPEvents: c.TextHTTPEvents, MaxDecodedBodyBytes: c.TextMaxDecodedBody,
		TLSUpgrade: c.TextTLSUpgrade, UDPProtocol: c.TextUDPProtocol,
	}
}

func (c DecryptConfig) ValidateDecryptOptions(pcapngText bool) error {
	if !pcapngText && c != (DecryptConfig{}) {
		return fmt.Errorf("decryption options require text capture mode with text-source=pcapng")
	}
	return c.DecryptOptions().Validate()
}
