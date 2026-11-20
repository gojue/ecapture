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

package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	bashProbe "github.com/gojue/ecapture/v2/internal/probe/bash"
	gotlsProbe "github.com/gojue/ecapture/v2/internal/probe/gotls"
	opensslProbe "github.com/gojue/ecapture/v2/internal/probe/openssl"
)

func decodeConfig(r *http.Request, create func() domain.Configuration) (*ConfigUpdate, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("request body is empty")
	}
	candidate := create()
	if _, core := candidate.(domain.TextSourceConfiguration); core {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			return nil, err
		}
		if fields == nil {
			return nil, fmt.Errorf("configuration must be a JSON object")
		}
		for field := range fields {
			switch strings.ToLower(field) {
			case "eventaddr", "logaddr", "logger_addr", "event_collector_addr", "event_rotate_size_mb", "event_rotate_seconds", "ecaptureq", "listen":
				return nil, fmt.Errorf("configuration field %q has been removed; configure outputs at process startup", field)
			case "output", "outputs", "config_listen", "config-listen", "stream_listen", "stream-listen":
				return nil, fmt.Errorf("configuration field %q is a process-lifetime setting and cannot be reloaded", field)
			}
		}
	}
	if err = json.Unmarshal(body, candidate); err != nil {
		return nil, err
	}
	patch, err := config.DecodeCommonConfigPatch(body)
	if err != nil {
		return nil, err
	}
	if err = patch.Apply(candidate); err != nil {
		return nil, err
	}
	return newConfigUpdate(candidate, patch), nil
}

// createOpensslConfig creates and decodes OpenSSL probe configuration from HTTP request
func createOpensslConfig(r *http.Request) (*ConfigUpdate, error) {
	return decodeConfig(r, func() domain.Configuration { return opensslProbe.NewConfig() })
}

// createGotlsConfig creates and decodes GoTLS probe configuration from HTTP request
func createGotlsConfig(r *http.Request) (*ConfigUpdate, error) {
	return decodeConfig(r, func() domain.Configuration { return gotlsProbe.NewConfig() })
}

// createBashConfig creates and decodes Bash probe configuration from HTTP request
func createBashConfig(r *http.Request) (*ConfigUpdate, error) {
	return decodeConfig(r, func() domain.Configuration { return bashProbe.NewConfig() })
}
