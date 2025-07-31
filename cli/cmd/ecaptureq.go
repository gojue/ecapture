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

import (
	"encoding/json"
	"fmt"

	"github.com/gojue/ecapture/pkg/ecaptureq"
)

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
	// 检查是否包含message键
	b, message, err := checkMessageKeyWithMap(data)
	if err != nil {
		return 0, fmt.Errorf("check message failed: %w", err)
	}
	if b {
		return eew.es.WriteEvent([]byte(message))
	}
	return eew.es.WriteEvent(data)
}

func checkMessageKeyWithMap(jsonData []byte) (bool, string, error) {
	var data map[string]interface{}

	// 解码JSON到map
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return false, "", fmt.Errorf("JSON解码失败: %w", err)
	}

	// 检查是否存在message键
	if message, exists := data["message"]; exists {
		// 尝试将message转换为字符串
		if msgStr, ok := message.(string); ok {
			return true, msgStr, nil
		}
		// 如果不是字符串类型，返回其字符串表示
		return true, "", nil
	}

	return false, "", nil
}
