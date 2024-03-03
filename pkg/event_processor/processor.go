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
	"ecapture/user/event"
	"fmt"
	"log"
	"sync"
)

const (
	MaxIncomingChanLen = 1024
	MaxParserQueueLen  = 1024
)

type EventProcessor struct {
	sync.Mutex
	// 收包，来自调用者发来的新事件
	incoming chan event.IEventStruct

	// key为 PID+UID+COMMON等确定唯一的信息
	workerQueue map[string]IWorker

	logger *log.Logger

	// output model
	isHex bool
}

func (this *EventProcessor) GetLogger() *log.Logger {
	return this.logger
}

func (this *EventProcessor) init() {
	this.incoming = make(chan event.IEventStruct, MaxIncomingChanLen)
	this.workerQueue = make(map[string]IWorker, MaxParserQueueLen)
}

// Write event 处理器读取事件
func (this *EventProcessor) Serve() {
	for {
		select {
		case e := <-this.incoming:
			this.dispatch(e)
		}
	}
}

func (this *EventProcessor) dispatch(e event.IEventStruct) {
	//this.logger.Printf("event ID:%s", e.GetUUID())
	var uuid string = e.GetUUID()
	found, eWorker := this.getWorkerByUUID(uuid)
	if !found {
		// ADD a new eventWorker into queue
		eWorker = NewEventWorker(e.GetUUID(), this)
		this.addWorkerByUUID(eWorker)
	}

	err := eWorker.Write(e)
	eWorker.Put() // never touch eWorker again
	if err != nil {
		//...
		this.GetLogger().Fatalf("write event failed , error:%v", err)
	}
}

//func (this *EventProcessor) Incoming() chan user.IEventStruct {
//	return this.incoming
//}

func (this *EventProcessor) getWorkerByUUID(uuid string) (bool, IWorker) {
	this.Lock()
	defer this.Unlock()
	var eWorker IWorker
	var found bool
	eWorker, found = this.workerQueue[uuid]
	if !found {
		return false, eWorker
	}
	eWorker.Get()
	return true, eWorker
}

func (this *EventProcessor) addWorkerByUUID(worker IWorker) {
	this.Lock()
	defer this.Unlock()
	this.workerQueue[worker.GetUUID()] = worker
	worker.Get()
}

// 每个worker调用该方法，从处理器中删除自己
func (this *EventProcessor) delWorkerByUUID(worker IWorker) {
	this.Lock()
	defer this.Unlock()
	delete(this.workerQueue, worker.GetUUID())
}

// Write event
// 外部调用者调用该方法
func (this *EventProcessor) Write(e event.IEventStruct) {
	select {
	case this.incoming <- e:
		return
	}
}

func (this *EventProcessor) Close() error {
	this.Lock()
	defer this.Unlock()
	if len(this.workerQueue) > 0 {
		return fmt.Errorf("EventProcessor.Close(): workerQueue is not empty:%d", len(this.workerQueue))
	}
	return nil
}

func NewEventProcessor(logger *log.Logger, isHex bool) *EventProcessor {
	var ep *EventProcessor
	ep = &EventProcessor{}
	ep.logger = logger
	ep.isHex = isHex
	ep.init()
	return ep
}
