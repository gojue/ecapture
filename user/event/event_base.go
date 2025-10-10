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

package event

import "encoding/json"

// Base 结构体与eCaptureQ 保持一致
type Base struct {
	Timestamp     int64  `json:"timestamp"`
	UUID          string `json:"uuid"`
	SrcIP         string `json:"src_ip"`
	SrcPort       uint32 `json:"src_port"`
	DstIP         string `json:"dst_ip"`
	DstPort       uint32 `json:"dst_port"`
	PID           int64  `json:"pid"`
	PName         string `json:"pname"`
	Type          uint32 `json:"type"` // 事件类型
	Length        uint32 `json:"length"`
	PayloadBase64 string `json:"payload"`
}

// Encode 将 PacketData 编码为 JSON 字节流
func (b *Base) Encode() ([]byte, error) {
	b.Length = uint32(len(b.PayloadBase64))
	return json.Marshal(b)
}

// Decode 从 JSON 字节流解码为 PacketData
func (b *Base) Decode(data []byte) error {
	return json.Unmarshal(data, b)
}
