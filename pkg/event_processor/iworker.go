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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gojue/ecapture/user/event"
)

type IWorker interface {

	// 定时器1 ，定时判断没有后续包，则解析输出

	// 定时器2， 定时判断没后续包，则通知上层销毁自己

	// 收包
	Write(event.IEventStruct) error
	GetUUID() string
	GetDestroyUUID() uint64
	IfUsed() bool
	Get()
	Put()
	CloseEventWorker()
}

const (
	MaxTickerCount = 10   // 1 Sencond/(eventWorker.ticker.C) = 10
	MaxChanLen     = 1024 // 包队列长度
	//MAX_EVENT_LEN    = 16 // 事件数组长度
)

// eventWorker有两种生命周期，一种由自己的定时器决定，另一种由外部Socket的生命周期决定
type LifeCycleState uint8

const (
	LifeCycleStateDefault LifeCycleState = iota
	LifeCycleStateSock
)

var (
	ErrEventWorkerIncomingFull  = errors.New("eventWorker Write failed, incoming chan is full")
	ErrEventWorkerOutcomingFull = errors.New("eventWorker Write failed, outComing chan is full")
)

type eventWorker struct {
	incoming chan event.IEventStruct
	//events      []user.IEventStruct
	originEvent      event.IEventStruct
	outComing        chan string
	status           ProcessStatus
	packetType       PacketType
	ticker           *time.Ticker
	tickerCount      uint8
	UUID             string
	uuidOutput       string
	DestroyUUID      uint64
	processor        *EventProcessor
	parser           IParser
	payload          *bytes.Buffer
	used             atomic.Bool
	closeChan        chan struct{} // 外部可以通过调用close(closeChan)来告知该eventWorker需要被关闭，起到信号量的作用，LifeCycleStateDefault的情况下应该是nil
	closeOnce        sync.Once     // 保证关闭操作只执行一次
	ewLifeCycleState LifeCycleState
}

func NewEventWorker(uuid string, processor *EventProcessor) IWorker {
	eWorker := &eventWorker{}
	eWorker.init(uuid, processor)
	go func() {
		eWorker.Run()
	}()
	return eWorker
}

func (ew *eventWorker) uuidParse(uuid string) {
	ew.uuidOutput = uuid
	ew.DestroyUUID = 0
	ew.ewLifeCycleState = LifeCycleStateDefault
	ew.closeChan = nil

	if !strings.HasPrefix(uuid, event.SocketLifecycleUUIDPrefix) {
		return
	}

	//uuid: sock:Pid_Tid_Comm_Fd_DataType_Tuple_Sock
	parts := strings.Split(uuid, "_")
	sock, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil || sock <= 0 {
		return
	}

	core := strings.TrimPrefix(uuid, event.SocketLifecycleUUIDPrefix)
	ew.uuidOutput = core[:strings.LastIndex(core, "_")]
	ew.DestroyUUID = sock
	ew.ewLifeCycleState = LifeCycleStateSock
	ew.closeChan = make(chan struct{})
	return
}

func (ew *eventWorker) init(uuid string, processor *EventProcessor) {
	ew.ticker = time.NewTicker(time.Millisecond * 100)
	ew.incoming = make(chan event.IEventStruct, MaxChanLen)
	ew.outComing = processor.outComing
	ew.status = ProcessStateInit
	ew.UUID = uuid
	ew.processor = processor
	ew.payload = bytes.NewBuffer(nil)
	ew.payload.Reset()
	ew.parser = nil
	ew.uuidParse(uuid)
}

func (ew *eventWorker) GetUUID() string {
	return ew.UUID
}

func (ew *eventWorker) CloseEventWorker() {
	if ew.closeChan != nil {
		ew.closeOnce.Do(func() {
			close(ew.closeChan)
		})
	}
}

func (ew *eventWorker) GetDestroyUUID() uint64 {
	return ew.DestroyUUID
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
	defer func() {
		// 设定状态、重置包类型
		ew.parser.Reset()
		ew.payload.Reset()
		ew.status = ProcessStateInit
		ew.packetType = PacketTypeNull
	}()
	if len(b) <= 0 {
		return nil
	}

	if ew.processor.isHex {
		b = []byte(hex.Dump(b))
	}

	eb := new(event.Base)
	oeb := ew.originEvent.Base()
	eb = &oeb
	eb.Type = uint32(ew.parser.ParserType())
	eb.UUID = ew.uuidOutput
	eb.PayloadBase64 = base64.StdEncoding.EncodeToString(b[:])

	//iWorker只负责写入，不应该打印。
	var err error
	_, ok := ew.processor.logger.(event.CollectorWriter)
	if ok {
		// 直接写入日志
		err = ew.writeToChan(fmt.Sprintf("PID:%d, Comm:%s, Src:%s:%d, Dest:%s:%d,\n%s", eb.PID, eb.PName, eb.SrcIP, eb.SrcPort, eb.DstIP, eb.DstPort, b))
	} else {
		var payload []byte
		payload, err = eb.Encode()
		if err != nil {
			return err
		}
		err = ew.writeToChan(string(payload))
	}
	return err
}

func (ew *eventWorker) writeEvent(e event.IEventStruct) {
	if ew.status != ProcessStateInit && ew.ewLifeCycleState == LifeCycleStateDefault {
		ew.Log(fmt.Sprintf("write events failed, unknow eventWorker status: %d", ew.status))
		return
	}

	tsize := int(ew.processor.truncateSize)
	//terminal write when reach the truncate size
	if tsize > 0 && ew.payload.Len() >= tsize {
		ew.payload.Truncate(tsize)
		ew.Log(fmt.Sprintf("Events truncated, size: %d bytes\n", tsize))
		return
	}
	ew.originEvent = e
	ew.payload.Write(e.Payload())
}

// 解析类型，输出
func (ew *eventWorker) parserEvents() []byte {
	ew.status = ProcessStateProcessing
	//LifeCycleStateSock ew shared the same parser during the running time
	if ew.parser == nil {
		ew.parser = NewParser(ew.payload.Bytes())
	}
	n, e := ew.parser.Write(ew.payload.Bytes())
	if e != nil {
		ew.Log(fmt.Sprintf("ew.parser uuid: %s type %d write payload %d bytes, error:%s", ew.UUID, ew.parser.ParserType(), n, e.Error()))
	}
	ew.status = ProcessStateDone
	return ew.parser.Display()
}

func (ew *eventWorker) Run() {
	/*
		This function is the main event loop of the eventWorker.
		It receives events through the `incoming` channel and processes them by calling `writeEvent()`.
		It uses a `ticker` to periodically detect idle states, if no events arrive for a long time,
		it triggers lifecycle management logic.

		The lifecycle manager supports two modes:
		1. LifeCycleStateSock: The worker runs continuously until the associated socket is destory.
		   After each `drainAndClose`, a new ticker is started to monitor further activity.
		2. LifeCycleStateDefault: The worker performs `delWorkerByUUID` and `drainAndClose` after a single timeout
	*/
	tickerRestartFlag := false
	for {
		select {
		case <-ew.ticker.C:
			// 输出包
			if ew.tickerCount > MaxTickerCount {
				if ew.ewLifeCycleState == LifeCycleStateSock {
					ew.drainAndClose()
					ew.tickerCount = 0
					tickerRestartFlag = true
					continue
				} else {
					ew.processor.delWorkerByUUID(ew)
					ew.drainAndClose()
					return
				}
			}
			ew.tickerCount++
		case e := <-ew.incoming:
			if tickerRestartFlag {
				ew.ticker = time.NewTicker(time.Millisecond * 100)
				tickerRestartFlag = false
			}
			ew.tickerCount = 0
			ew.writeEvent(e)
		// LifeCycleStateDefault ew will never touch it as its closeChan is nil
		case <-ew.closeChan:
			ew.processor.delWorkerByUUID(ew)
			ew.drainAndClose()
			return
		}
	}
}

func (ew *eventWorker) drainAndClose() {
	/*
		When returned from drainAndClose(), there are two possibilities:
		1) no routine can touch it.
		2) one routine can still touch ew because getWorkerByUUID()
		*happen before* drainAndClose() for LifeCycleStateDefault ew

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

// Log is a simple logging function for eventWorker. 临时输出。 TODO : 需要重新设计
func (ew *eventWorker) Log(payload string) {
	fmt.Println("eventWorker: ", payload)
}
