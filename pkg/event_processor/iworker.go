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
	"ecapture/user/event"
	"encoding/hex"
	"time"
)

type IWorker interface {

	// 定时器1 ，定时判断没有后续包，则解析输出

	// 定时器2， 定时判断没后续包，则通知上层销毁自己

	// 收包
	Write(event.IEventStruct) error
	GetUUID() string
}

const (
	MaxTickerCount = 10 // 1 Sencond/(eventWorker.ticker.C) = 10
	MaxChanLen     = 16 // 包队列长度
	//MAX_EVENT_LEN    = 16 // 事件数组长度
)

type eventWorker struct {
	incoming chan event.IEventStruct
	//events      []user.IEventStruct
	status      ProcessStatus
	packetType  PacketType
	ticker      *time.Ticker
	tickerCount uint8
	UUID        string
	processor   *EventProcessor
	parser      IParser
	payload     *bytes.Buffer
}

func NewEventWorker(uuid string, processor *EventProcessor) IWorker {
	eWorker := &eventWorker{}
	eWorker.init(uuid, processor)
	go func() {
		eWorker.Run()
	}()
	return eWorker
}

func (ew *eventWorker) init(uuid string, processor *EventProcessor) {
	ew.ticker = time.NewTicker(time.Millisecond * 100)
	ew.incoming = make(chan event.IEventStruct, MaxChanLen)
	ew.status = ProcessStateInit
	ew.UUID = uuid
	ew.processor = processor
	ew.payload = bytes.NewBuffer(nil)
	ew.payload.Reset()
}

func (ew *eventWorker) GetUUID() string {
	return ew.UUID
}

func (ew *eventWorker) Write(e event.IEventStruct) error {
	ew.incoming <- e
	return nil
}

// 输出包内容
func (ew *eventWorker) Display() {

	//  输出包内容
	b := ew.parserEvents()
	defer ew.parser.Reset()
	if len(b) <= 0 {
		return
	}

	if ew.processor.isHex {
		b = []byte(hex.Dump(b))
	}

	// TODO 格式化的终端输出
	// 重置状态
	ew.processor.GetLogger().Printf("UUID:%s, Name:%s, Type:%d, Length:%d", ew.UUID, ew.parser.Name(), ew.parser.ParserType(), len(b))
	ew.processor.GetLogger().Println("\n" + string(b))
	//ew.parser.Reset()
	// 设定状态、重置包类型
	ew.status = ProcessStateInit
	ew.packetType = PacketTypeNull
}

func (ew *eventWorker) writeEvent(e event.IEventStruct) {
	if ew.status != ProcessStateInit {
		ew.processor.GetLogger().Printf("write events failed, unknow eventWorker status")
		return
	}
	ew.payload.Write(e.Payload())
}

// 解析类型，输出
func (ew *eventWorker) parserEvents() []byte {
	ew.status = ProcessStateProcessing
	parser := NewParser(ew.payload.Bytes())
	ew.parser = parser
	n, e := ew.parser.Write(ew.payload.Bytes())
	if e != nil {
		ew.processor.GetLogger().Printf("ew.parser write payload %d bytes, error:%v", n, e)
	}
	ew.status = ProcessStateDone
	return ew.parser.Display()
}

func (ew *eventWorker) Run() {
	for {
		select {
		case _ = <-ew.ticker.C:
			// 输出包
			if ew.tickerCount > MaxTickerCount {
				//ew.processor.GetLogger().Printf("eventWorker TickerCount > %d, event closed.", MaxTickerCount)
				ew.Close()
				return
			}
			ew.tickerCount++
		case e := <-ew.incoming:
			// reset tickerCount
			ew.tickerCount = 0
			ew.writeEvent(e)
		}
	}

}

func (ew *eventWorker) Close() {
	// 即将关闭， 必须输出结果
	ew.ticker.Stop()
	ew.Display()
	ew.tickerCount = 0
	ew.processor.delWorkerByUUID(ew)
}
