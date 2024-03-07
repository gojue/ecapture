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
	"context"
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
	PacketTypeBash
)

const (
	ParserTypeNull ParserType = iota
	ParserTypeHttpRequest
	ParserTypeHttp2Request
	ParserTypeHttpResponse
	ParserTypeHttp2Response
	ParserTypeWebSocket
	ParserTypeBash
)

type IParser interface {
	detect(ctx context.Context, b []byte) error
	Write(b []byte) (int, error)
	ParserType() ParserType
	PacketType() PacketType
	//Body() []byte
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

// GetModules 获取modules列表
func GetAllModules() map[string]IParser {
	return parsers
}

// GetModules 获取modules列表
func GetModuleByName(name string) IParser {
	return parsers[name]
}

func NewParser(ctx context.Context, payload []byte) IParser {
	if len(payload) > 0 {
		var newParser IParser
		for _, parser := range GetAllModules() {
			err := parser.detect(ctx, payload)
			if err == nil {
				switch parser.ParserType() {
				case ParserTypeHttpRequest:
					newParser = new(HTTPRequest)
				case ParserTypeHttpResponse:
					newParser = new(HTTPResponse)
				case ParserTypeHttp2Request:
					// TODO support HTTP2 request
					// via golang.org/x/net/http2
					//hpack.NewEncoder(buf)
				case ParserTypeHttp2Response:
					// TODO  support HTTP2 response
				case ParserTypeBash:
					newParser = new(BashParser)
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

func (this *DefaultParser) ParserType() ParserType {
	return ParserTypeNull
}

func (this *DefaultParser) PacketType() PacketType {
	return PacketTypeNull
}

func (this *DefaultParser) Write(b []byte) (int, error) {
	this.isdone = true
	return this.reader.Write(b)
}

// DefaultParser 检测包类型
func (this *DefaultParser) detect(ctx context.Context, b []byte) error {
	return nil
}

func (this *DefaultParser) Name() string {
	return "DefaultParser"
}

func (this *DefaultParser) IsDone() bool {
	return this.isdone
}

func (this *DefaultParser) Init() {
	this.reader = bytes.NewBuffer(nil)
}

func (this *DefaultParser) Display() []byte {
	b := this.reader.Bytes()
	if len(b) <= 0 {
		return []byte{}
	}
	if b[0] < 32 || b[0] > 126 {
		return []byte(hex.Dump(b))
	}
	return []byte(CToGoString(this.reader.Bytes()))
}

func (this *DefaultParser) Reset() {
	this.isdone = false
	this.reader.Reset()
}
