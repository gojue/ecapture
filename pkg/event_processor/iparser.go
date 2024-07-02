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

package event_processor

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

type ProcessStatus uint8
type PacketType uint8
type ParserType uint8

const (
	ProcessStateInit ProcessStatus = iota
	ProcessStateProcessing
	ProcessStateDone
)

const (
	PacketTypeNull PacketType = iota
	PacketTypeUnknow
	PacketTypeGzip
	PacketTypeWebSocket
)

const (
	ParserTypeNull ParserType = iota
	ParserTypeHttpRequest
	ParserTypeHttp2Request
	ParserTypeHttpResponse
	ParserTypeHttp2Response
	ParserTypeWebSocket
)

type IParser interface {
	detect(b []byte) error
	Write(b []byte) (int, error)
	ParserType() ParserType
	PacketType() PacketType
	// Name Body() []byte
	Name() string
	IsDone() bool
	Init()
	Display() []byte
	Reset()
}

var parsers = make(map[string]IParser)

func Register(p IParser) {
	if p == nil {
		panic("Register Parser is nil")
	}
	name := p.Name()
	if _, dup := parsers[name]; dup {
		panic(fmt.Sprintf("Register called twice for Parser %s", name))
	}
	parsers[name] = p
}

// GetAllModules  获取modules列表
func GetAllModules() map[string]IParser {
	return parsers
}

// GetModuleByName  获取modules列表
func GetModuleByName(name string) IParser {
	return parsers[name]
}

func NewParser(payload []byte) IParser {
	if len(payload) > 0 {
		var newParser IParser
		for _, parser := range GetAllModules() {
			err := parser.detect(payload)
			if err == nil {
				switch parser.ParserType() {
				case ParserTypeHttpRequest:
					newParser = new(HTTPRequest)
				case ParserTypeHttpResponse:
					newParser = new(HTTPResponse)
				case ParserTypeHttp2Request:
					newParser = new(HTTP2Request)
				case ParserTypeHttp2Response:
					newParser = new(HTTP2Response)
				default:
					newParser = new(DefaultParser)
				}
				break
			}
		}
		if newParser == nil {
			newParser = new(DefaultParser)
		}
		newParser.Init()
		return newParser
	}
	var np = &DefaultParser{}
	np.Init()
	return np
}

type DefaultParser struct {
	reader *bytes.Buffer
	isdone bool
}

func (dp *DefaultParser) ParserType() ParserType {
	return ParserTypeNull
}

func (dp *DefaultParser) PacketType() PacketType {
	return PacketTypeNull
}

func (dp *DefaultParser) Write(b []byte) (int, error) {
	dp.isdone = true
	return dp.reader.Write(b)
}

// DefaultParser 检测包类型
func (dp *DefaultParser) detect(b []byte) error {
	return nil
}

func (dp *DefaultParser) Name() string {
	return "DefaultParser"
}

func (dp *DefaultParser) IsDone() bool {
	return dp.isdone
}

func (dp *DefaultParser) Init() {
	dp.reader = bytes.NewBuffer(nil)
}

func (dp *DefaultParser) Display() []byte {
	b := dp.reader.Bytes()
	if len(b) <= 0 {
		return []byte{}
	}
	if b[0] < 32 || b[0] > 126 {
		return []byte(hex.Dump(b))
	}
	return []byte(CToGoString(dp.reader.Bytes()))
}

func (dp *DefaultParser) Reset() {
	dp.isdone = false
	dp.reader.Reset()
}
