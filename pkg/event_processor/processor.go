package event_processor

import (
	"fmt"
	"log"
	"sync"
)

const (
	MAX_INCOMING_CHAN_LEN = 1024
	MAX_PARSER_QUEUE_LEN  = 1024
)

type EventProcessor struct {
	sync.Mutex
	// 收包，来自调用者发来的新事件
	incoming chan IEventStruct

	// key为 PID+UID+COMMON等确定唯一的信息
	workerQueue map[string]IWorker

	logger *log.Logger
}

func (this *EventProcessor) GetLogger() *log.Logger {
	return this.logger
}

func (this *EventProcessor) init() {
	this.incoming = make(chan IEventStruct, MAX_INCOMING_CHAN_LEN)
	this.workerQueue = make(map[string]IWorker, MAX_PARSER_QUEUE_LEN)
}

// Write event 处理器读取事件
func (this *EventProcessor) Serve() {
	for {
		select {
		case event := <-this.incoming:
			this.dispatch(event)
		}
	}
}

func (this *EventProcessor) dispatch(event IEventStruct) {
	var uuid string = event.GetUUID()
	found, eWorker := this.getWorkerByUUID(uuid)
	if !found {
		// ADD a new eventWorker into queue
		eWorker = NewEventWorker(event.GetUUID(), this)
		this.addWorkerByUUID(eWorker)
	}

	err := eWorker.Write(event)
	if err != nil {
		//...
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
	return true, eWorker
}

func (this *EventProcessor) addWorkerByUUID(worker IWorker) {
	this.Lock()
	defer this.Unlock()
	this.workerQueue[worker.GetUUID()] = worker
}

// 每个worker调用该方法，从处理器中删除自己
func (this *EventProcessor) delWorkerByUUID(worker IWorker) {
	this.Lock()
	defer this.Unlock()
	delete(this.workerQueue, worker.GetUUID())
}

// Write event
// 外部调用者调用该方法
func (this *EventProcessor) Write(event IEventStruct) {
	select {
	case this.incoming <- event:
		return
	}
}

func (this *EventProcessor) Close() error {
	if len(this.workerQueue) > 0 {
		return fmt.Errorf("EventProcessor.Close(): workerQueue is not empty:%d", len(this.workerQueue))
	}
	return nil
}

func NewEventProcessor(logger *log.Logger) *EventProcessor {
	var ep *EventProcessor
	ep = &EventProcessor{}
	ep.logger = logger
	ep.init()
	return ep
}
