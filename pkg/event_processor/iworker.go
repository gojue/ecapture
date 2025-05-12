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
	"errors"
	"fmt"
	"github.com/gojue/ecapture/user/event"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type IWorker interface {

	// 定时器1 ，定时判断没有后续包，则解析输出

	// 定时器2， 定时判断没后续包，则通知上层销毁自己

	// 收包
	Write(event.IEventStruct) error
	GetUUID() string
	GetSock() uint64
	IfUsed() bool
	Get()
	Put()
	Done()
}

const (
	MaxTickerCount = 10   // 1 Sencond/(eventWorker.ticker.C) = 10
	MaxChanLen     = 1024 // 包队列长度
	//MAX_EVENT_LEN    = 16 // 事件数组长度
)

var (
	ErrEventWorkerIncomingFull  = errors.New("eventWorker Write failed, incoming chan is full")
	ErrEventWorkerOutcomingFull = errors.New("eventWorker Write failed, outComing chan is full")
)

type eventWorker struct {
	incoming chan event.IEventStruct
	//events      []user.IEventStruct
	outComing   chan string
	status      ProcessStatus
	packetType  PacketType
	ticker      *time.Ticker
	tickerCount uint8
	UUID        string
	Sock        uint64
	processor   *EventProcessor
	parser      IParser
	payload     *bytes.Buffer
	used        atomic.Bool
	done        chan struct{}
}

func NewEventWorker(uuid string, processor *EventProcessor) IWorker {
	eWorker := &eventWorker{}
	eWorker.init(uuid, processor)
	go func() {
		eWorker.Run()
	}()
	return eWorker
}

func getSock(uuid string) uint64 {
	//uuid: Pid_Tid_Comm_Fd_DataType_Tuple_Sock
	uuidFileCount := 7
	parts := strings.SplitN(uuid, "_", uuidFileCount)
	if len(parts) != uuidFileCount {
		return 0
	}

	sock, err := strconv.ParseUint(parts[uuidFileCount-1], 10, 64)
	if err != nil {
		return 0
	}
	return sock
}

func (ew *eventWorker) init(uuid string, processor *EventProcessor) {
	ew.ticker = time.NewTicker(time.Millisecond * 100)
	ew.incoming = make(chan event.IEventStruct, MaxChanLen)
	ew.outComing = processor.outComing
	ew.status = ProcessStateInit
	ew.UUID = uuid
	ew.Sock = getSock(uuid)
	ew.processor = processor
	ew.payload = bytes.NewBuffer(nil)
	ew.payload.Reset()
	ew.done = make(chan struct{})
	ew.parser = nil
}

func (ew *eventWorker) GetUUID() string {
	return ew.UUID
}

func (ew *eventWorker) GetSock() uint64 {
	return ew.Sock
}

func (ew *eventWorker) Write(e event.IEventStruct) error {
	var err error
	select {
	case ew.incoming <- e:
	default:
		err = ErrEventWorkerIncomingFull
	}
	return err
}

func (ew *eventWorker) writeToChan(s string) error {
	var err error
	select {
	case ew.outComing <- s:
	default:
		err = ErrEventWorkerOutcomingFull
	}
	return err
}

// Display 输出包内容
func (ew *eventWorker) Display() error {
	//  输出包内容
	b := ew.parserEvents()
	defer ew.parser.Reset()
	if len(b) <= 0 {
		return nil
	}

	if ew.processor.isHex {
		b = []byte(hex.Dump(b))
	}

	//iWorker只负责写入，不应该打印。
	//uuid: Pid_Tid_Comm_Fd_DataType_Tuple_Sock
	uuid := ew.UUID
	uuidOutput := uuid[:strings.LastIndex(uuid, "_")]
	e := ew.writeToChan(fmt.Sprintf("UUID:%s, Name:%s, Type:%d, Length:%d\n%s\n", uuidOutput, ew.parser.Name(), ew.parser.ParserType(), len(b), b))
	//ew.parser.Reset()
	// 设定状态、重置包类型
	ew.payload.Reset()
	ew.status = ProcessStateInit
	ew.packetType = PacketTypeNull
	return e
}

func (ew *eventWorker) writeEvent(e event.IEventStruct) {
	if ew.status != ProcessStateInit {
		_ = ew.writeToChan("write events failed, unknow eventWorker status")
	}
	ew.payload.Write(e.Payload())
}

// 解析类型，输出
func (ew *eventWorker) parserEvents() []byte {
	ew.status = ProcessStateProcessing
	tsize := int(ew.processor.truncateSize)
	if tsize > 0 && ew.payload.Len() > tsize {
		ew.payload.Truncate(tsize)
		_ = ew.writeToChan(fmt.Sprintf("Events truncated, size: %d bytes\n", tsize))
	}
	if ew.parser == nil {
		ew.parser = NewParser(ew.payload.Bytes())
	}
	n, e := ew.parser.Write(ew.payload.Bytes())
	if e != nil {
		_ = ew.writeToChan(fmt.Sprintf("ew.parser write payload %d bytes, error:%v", n, e))
	}
	ew.status = ProcessStateDone
	return ew.parser.Display()
}

func drainAndClose(ew *eventWorker) {
	/*
		When returned from drainAndClose(), there are two possibilities:
		1) no routine can touch it.
		2) one routine can still touch ew because getWorkerByUUID()
		*happen before* drainAndClose()

		When no routine can touch it (i.e.,ew.IfUsed == false),
		we just drain the ew.incoming and return.

		When one routine can touch it (i.e.,ew.IfUsed == true), we ensure
		that we only return after the routine can not touch it
		(i.e.,ew.IfUsed == false). At this point, we can ensure that no
		other routine will touch it and send events through the ew.incoming.
		So, we return.
	*/
	for {
		select {
		case e := <-ew.incoming:
			ew.writeEvent(e)
		default:
			if ew.IfUsed() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			ew.Close()
			return
		}
	}
}

func (ew *eventWorker) Run() {
	restartFlag := false
	for {
		select {
		case <-ew.done:
			ew.ticker.Stop()
			return
		case <-ew.ticker.C:
			// 输出包
			if ew.tickerCount > MaxTickerCount {
				drainAndClose(ew)
				if ew.GetSock() == 0 {
					/*
					   sock == 0 means get tuple failed when deal ssl_data
					   eWork should not be shared between events uuid is 0.
					*/
					ew.processor.delWorkerByUUID(ew)
					return
				} else {
					restartFlag = true
					continue
				}
			}
			ew.tickerCount++
		case e := <-ew.incoming:
			if restartFlag {
				ew.ticker = time.NewTicker(time.Millisecond * 100)
				restartFlag = false
			}
			// reset tickerCount
			ew.tickerCount = 0
			ew.writeEvent(e)
		}
	}
}

func (ew *eventWorker) Close() {
	// 即将关闭， 必须输出结果
	ew.ticker.Stop()
	_ = ew.Display()
	ew.tickerCount = 0
}

func (ew *eventWorker) Get() {
	if !ew.used.CompareAndSwap(false, true) {
		panic("unexpected behavior and incorrect usage for eventWorker")
	}
}

func (ew *eventWorker) Put() {
	if !ew.used.CompareAndSwap(true, false) {
		panic("unexpected behavior and incorrect usage for eventWorker")
	}
}

func (ew *eventWorker) IfUsed() bool {

	return ew.used.Load()
}

func (ew *eventWorker) Done() {
	close(ew.done)
}
