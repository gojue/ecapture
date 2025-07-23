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

package event

type EventType uint8

const (
	// EventTypeOutput upload to server or write to logfile.
	EventTypeOutput EventType = iota

	// EventTypeModuleData set as module cache data
	EventTypeModuleData

	// EventTypeEventProcessor display by event_processor.
	EventTypeEventProcessor
)

const SocketLifecycleUUIDPrefix = "sock:"

type IEventStruct interface {
	Decode(payload []byte) (err error)
	Payload() []byte
	PayloadLen() int
	String() string
	StringHex() string
	Clone() IEventStruct
	EventType() EventType
	GetUUID() string
}
