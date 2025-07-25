// Copyright 2025 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

import "github.com/gojue/ecapture/pkg/ecaptureq"

// ecaptureQLogWriter
type ecaptureQLogWriter struct {
	es *ecaptureq.Server
}

func (eew ecaptureQLogWriter) Write(data []byte) (n int, e error) {
	return eew.es.WriteLog(data)
}

type ecaptureQEventWriter struct {
	es *ecaptureq.Server
}

func (eew ecaptureQEventWriter) Write(data []byte) (n int, e error) {
	return eew.es.WriteEvent(data)
}
