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

//go:generate stringer -type=Status
type Status uint8

const (
	RespOK Status = iota
	RespErrorInvaildRequest
	RespErrorInternalServer
	RespErrorNotFound
	RespConfigDecodeFailed
	RespConfigCheckFailed
	RespSendToChanFailed
)

// Resp -
type Resp struct {
	Code       Status      `json:"code"`
	ModuleType string      `json:"module_type"` // config.ModuleType
	Msg        string      `json:"msg"`
	Data       interface{} `json:"data"`
}
