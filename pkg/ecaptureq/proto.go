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

package ecaptureq

import "encoding/json"

type eqMessageType uint8

const (
	LogTypeHeartBeat  eqMessageType = 0
	LogTypeProcessLog eqMessageType = 1
	LogTypeEvent      eqMessageType = 2
)

type eqMessage struct {
	LogType eqMessageType   `json:"log_type"`
	Payload json.RawMessage `json:"payload"`
}

// Encode 将 eqMessage 编码为 JSON 字节流
func (m *eqMessage) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// Decode 从 JSON 字节流解码为 eqMessage
func (m *eqMessage) Decode(data []byte) error {
	return json.Unmarshal(data, m)
}

// PacketData 结构体与您 Rust 项目中的 core::models::PacketData 完全对应。
// 我们使用 `json:"..."` 标签来确保生成的 JSON 字段名与前端期望的一致。
type PacketData struct {
	Timestamp     int64  `json:"timestamp"`
	SrcIP         string `json:"src_ip"`
	SrcPort       uint32 `json:"src_port"`
	DstIP         string `json:"dst_ip"`
	DstPort       uint32 `json:"dst_port"`
	PID           int32  `json:"pid"`
	PName         string `json:"pname"`
	Type          string `json:"type"` // 对应 Rust 的 `r#type`
	Length        uint32 `json:"length"`
	PayloadBase64 string `json:"payload_base64"`
}

// Encode 将 PacketData 编码为 JSON 字节流
func (p *PacketData) Encode() ([]byte, error) {
	return json.Marshal(p)
}

// Decode 从 JSON 字节流解码为 PacketData
func (p *PacketData) Decode(data []byte) error {
	return json.Unmarshal(data, p)
}

type HeartbeatMessage struct {
	Timestamp int64  `json:"timestamp"`
	Count     int32  `json:"count"`
	Message   string `json:"message"`
}
