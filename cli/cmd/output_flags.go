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

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

func bindDecryptFlags(command *cobra.Command, cfg *config.DecryptConfig) {
	flags := command.PersistentFlags()
	flags.BoolVar(&cfg.TextRaw, "text-raw", false, "emit authenticated TLS/QUIC bytes and datagrams instead of parsed messages (pcapng text source)")
	flags.StringVar(&cfg.TextProtocol, "text-protocol", "", "application parser: dot, doh, doq, mqtt or redis; empty detects HTTP/WebSocket (pcapng text source)")
	flags.BoolVar(&cfg.TextHTTPEvents, "text-http-events", false, "emit incremental HTTP, SSE and HTTP/2 gRPC events (pcapng text source)")
	flags.Int64Var(&cfg.TextMaxDecodedBody, "text-max-decoded-body", 0, "maximum decoded gzip bytes per HTTP message; requires text-http-events, zero keeps encoded bytes")
	flags.StringVar(&cfg.TextTLSUpgrade, "text-tls-upgrade", "", "TLS negotiation: smtp, imap, pop3, ldap, postgres, mysql, connect or https-connect (pcapng text source)")
	flags.StringVar(&cfg.TextUDPProtocol, "text-udp-protocol", "", "UDP decryptor: quic (default) or dtls (pcapng text source)")
}

func normalizeTLSOutputFlags(command *cobra.Command, mode, textSource string, keylogFile, pcapFile *string) error {
	mode = strings.ToLower(mode)
	if (mode == "" || mode == handlers.ModeText) && strings.EqualFold(textSource, handlers.TextSourcePcapng) {
		if flag := command.Flag("keylogfile"); flag == nil || !flag.Changed {
			*keylogFile = ""
		}
		if flag := command.Flag("pcapfile"); flag == nil || !flag.Changed {
			*pcapFile = ""
		}
		return nil
	}
	eventFlag := command.Flag("eventaddr")
	if eventFlag == nil || !eventFlag.Changed {
		return nil
	}
	switch mode {
	case handlers.ModeKey, handlers.ModeKeylog:
		if flag := command.Flag("keylogfile"); flag != nil && flag.Changed {
			return fmt.Errorf("--eventaddr and --keylogfile cannot both select the primary keylog destination")
		}
		*keylogFile = ""
	case handlers.ModePcap, handlers.ModePcapng:
		if flag := command.Flag("pcapfile"); flag != nil && flag.Changed {
			return fmt.Errorf("--eventaddr and --pcapfile cannot both select the primary pcapng destination")
		}
		*pcapFile = ""
	}
	return nil
}
