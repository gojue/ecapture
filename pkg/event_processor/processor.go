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
	"fmt"
	"io"
	"sync"

	"github.com/gojue/ecapture/user/event"
)

const (
	MaxIncomingChanLen = 1024
	MaxParserQueueLen  = 1024
)

type EventProcessor struct {
	sync.Mutex
	isClosed bool // 是否已关闭
	// 收包，来自调用者发来的新事件
	incoming chan event.IEventStruct
	// send to output
	outComing chan string
	// key为 PID+UID+COMMON等确定唯一的信息
	workerQueue map[string]IWorker
	// log
	logger io.Writer

	closeChan chan bool
	errChan   chan error

	// output model
	isHex        bool
	truncateSize uint64
}

func (ep *EventProcessor) GetLogger() io.Writer {
	return ep.logger
}

func (ep *EventProcessor) init() {
	ep.incoming = make(chan event.IEventStruct, MaxIncomingChanLen)
	ep.outComing = make(chan string, MaxIncomingChanLen)
	ep.closeChan = make(chan bool)
	ep.errChan = make(chan error, 16)
	ep.workerQueue = make(map[string]IWorker, MaxParserQueueLen)
}

// Serve Write event 处理器读取事件
func (ep *EventProcessor) Serve() error {
	var err error
	for {
		select {
		case eventStruct := <-ep.incoming:
			err = ep.dispatch(eventStruct)
			if err != nil {
				// 不返回error是合理的做法，因为个别事件处理失败不应该影响整个处理器的关闭。
				// 但是，需要将这个错误抛给的调用着，让调用者决定是否关闭处理器
				select {
				case ep.errChan <- err:
				default:
				}
			}
		case s := <-ep.outComing:
			_, _ = ep.GetLogger().Write([]byte(s))
		case _ = <-ep.closeChan:
			return nil
		}
	}
}

func (ep *EventProcessor) dispatch(e event.IEventStruct) error {
	//ep.logger.Printf("event ID:%s", e.GetUUID())
	var uuid = e.GetUUID()
	found, eWorker := ep.getWorkerByUUID(uuid)
	if !found {
		// ADD a new eventWorker into queue
		eWorker = NewEventWorker(e.GetUUID(), ep)
		ep.addWorkerByUUID(eWorker)
	}

	err := eWorker.Write(e)
	eWorker.Put() // never touch eWorker again
	if err != nil {
		//...
		//ep.GetLogger().Write("write event failed , error:%w", err)
		return err
	}
	return nil
}

//func (this *EventProcessor) Incoming() chan user.IEventStruct {
//	return this.incoming
//}

func (ep *EventProcessor) getWorkerByUUID(uuid string) (bool, IWorker) {
	ep.Lock()
	defer ep.Unlock()
	var eWorker IWorker
	var found bool
	eWorker, found = ep.workerQueue[uuid]
	if !found {
		return false, eWorker
	}
	eWorker.Get()
	return true, eWorker
}

func (ep *EventProcessor) addWorkerByUUID(worker IWorker) {
	ep.Lock()
	defer ep.Unlock()
	ep.workerQueue[worker.GetUUID()] = worker
	worker.Get()
}

// 每个worker调用该方法，从处理器中删除自己
func (ep *EventProcessor) delWorkerByUUID(worker IWorker) {
	ep.Lock()
	defer ep.Unlock()
	delete(ep.workerQueue, worker.GetUUID())
}

// Write event
// 外部调用者调用该方法
func (ep *EventProcessor) Write(e event.IEventStruct) {
	if ep.isClosed {
		return
	}
	select {
	case ep.incoming <- e:
		return
	default:
		// 如果队列满了，丢弃事件
	}
}

func (ep *EventProcessor) Close() error {
	ep.Lock()
	defer ep.Unlock()
	if ep.isClosed {
		return nil
	}
	ep.isClosed = true
	close(ep.closeChan)
	close(ep.incoming)
	if len(ep.workerQueue) > 0 {
		return fmt.Errorf("EventProcessor.Close(): workerQueue is not empty:%d", len(ep.workerQueue))
	}
	return nil
}

func (ep *EventProcessor) ErrorChan() chan error {
	return ep.errChan
}

func NewEventProcessor(logger io.Writer, isHex bool, truncateSize uint64) *EventProcessor {
	var ep *EventProcessor
	ep = &EventProcessor{}
	ep.logger = logger
	ep.isHex = isHex
	ep.truncateSize = truncateSize
	ep.isClosed = false
	ep.init()
	return ep
}
