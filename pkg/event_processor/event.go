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
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// Type 事件类型
type Type uint8

const (
	// TypeOutput 输出事件
	TypeOutput Type = iota
	// TypeEventProcessor 由event processor处理的事件
	TypeEventProcessor
	// TypeModuleData 模块缓存数据事件
	TypeModuleData
)

// SocketLifecycleUUIDPrefix Socket生命周期UUID前缀
const SocketLifecycleUUIDPrefix = "sock:"

// IEventStruct 事件接口定义
// 这个接口定义了event_processor需要的事件方法
type IEventStruct interface {
	// GetUUID 获取事件的唯一标识符
	GetUUID() string
	
	// Payload 获取事件的payload数据
	Payload() []byte
	
	// Base 获取事件的基本信息
	Base() Base
	
	// ToProtobufEvent 转换为protobuf事件
	ToProtobufEvent() *pb.Event
	
	// Clone 克隆事件
	Clone() IEventStruct
	
	// EventType 获取事件类型
	EventType() Type
}

// Base 事件基础信息
type Base struct {
	Timestamp int64  // 时间戳
	UUID      string // 唯一标识符
	PID       int64  // 进程ID
	PName     string // 进程名称
	SrcIP     string // 源IP
	SrcPort   uint16 // 源端口
	DstIP     string // 目标IP
	DstPort   uint16 // 目标端口
	Type      uint32 // 事件类型
}

// CollectorWriter 收集器写入接口
// 用于识别日志输出器是否是collector类型
type CollectorWriter interface {
	Write(p []byte) (n int, err error)
}
