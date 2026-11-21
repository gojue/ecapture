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
	"strings"

	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

const (
	perfReorderHelp    = "Order timestamped events across CPUs by kernel time, separately for each perf map"
	perfReorderLagHelp = "Reordering window in `milliseconds` for --perf-reorder. Zero uses the default."
)

func bindDecryptFlags(command *cobra.Command, cfg *config.DecryptConfig) {
	flags := command.PersistentFlags()
	flags.BoolVar(&cfg.TextRaw, "text-raw", false, "Emit decrypted TLS bytes, QUIC stream chunks, and QUIC datagrams without application parsing")
	flags.StringVar(&cfg.TextProtocol, "text-protocol", "", "Parse the specified application `protocol` (dot, doh, doq, mqtt, or redis). By default, detect HTTP and WebSocket traffic.")
	flags.BoolVar(&cfg.TextHTTPEvents, "text-http-events", false, "Emit HTTP headers and body chunks as they arrive, including server-sent events and HTTP/2 gRPC messages")
	flags.Int64Var(&cfg.TextMaxDecodedBody, "text-max-decoded-body", 0, "With --text-http-events, limit gzip expansion to this many `bytes` per HTTP message. Use 0 to keep bodies compressed.")
	flags.StringVar(&cfg.TextTLSUpgrade, "text-tls-upgrade", "", "Follow a TLS upgrade or proxy `protocol` (smtp, imap, pop3, ldap, postgres, mysql, connect, or https-connect). By default, expect TLS from the start.")
	flags.StringVar(&cfg.TextUDPProtocol, "text-udp-protocol", "", "Select the UDP `protocol` (quic by default, or dtls for DTLS 1.2)")
}

func normalizeTLSOutputFlags(command *cobra.Command, mode string, textSource, keylogFile, pcapFile *string) error {
	mode = strings.ToLower(mode)
	if flag := command.Flag("text-source"); flag != nil && !flag.Changed {
		*textSource = ""
	}
	source, err := handlers.NormalizeTextSource(mode, *textSource)
	if err != nil {
		return err
	}
	*textSource = source
	if (mode == "" || mode == handlers.ModeText) && source == handlers.TextSourcePcapng {
		if flag := command.Flag("keylogfile"); flag == nil || !flag.Changed {
			*keylogFile = ""
		}
		if flag := command.Flag("pcapfile"); flag == nil || !flag.Changed {
			*pcapFile = ""
		}
		return nil
	}
	return nil
}
