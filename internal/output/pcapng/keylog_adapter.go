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

package pcapng

import "bytes"

// KeylogAdapter lets a keylog handler add TLS secrets to a borrowed Session.
type KeylogAdapter struct {
	session *Session
}

func (w *KeylogAdapter) Name() string {
	return "pcapng-keylog-adapter"
}

func (w *KeylogAdapter) Flush() error {
	return w.session.FlushKeylogs()
}

// Close is intentionally a no-op. KeylogAdapter borrows the pcapng session;
// PcapngHandler is the sole close owner.
func (w *KeylogAdapter) Close() error { return nil }

func NewKeylogAdapter(session *Session) *KeylogAdapter {
	return &KeylogAdapter{session: session}
}

func (w *KeylogAdapter) Write(p []byte) (n int, err error) {
	// Create a copy to avoid modifying the provided buffer
	record := bytes.TrimRight(p, "\r\n")
	data := make([]byte, len(record)+1)
	copy(data, record)
	data[len(record)] = '\n'
	return len(p), w.session.WriteKeyLog(data)
}
