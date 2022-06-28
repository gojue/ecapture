package event_processor

import (
	"ecapture/user"
)

const (
	MAX_INCOMING_CHAN_LEN = 1024
	MAX_PARSER_QUEUE_LEN  = 1024
)

type EventProcessor struct {
	// 收包，来自调用者发来的新事件
	incoming chan user.IEventStruct

	// key为 PID+UID+COMMON等确定唯一的信息
	workerQueue map[string]IWorker
}

func (this *EventProcessor) init() {

	this.incoming = make(chan user.IEventStruct, MAX_INCOMING_CHAN_LEN)
	this.workerQueue = make(map[string]IWorker, MAX_PARSER_QUEUE_LEN)
}

func (this *EventProcessor) Serve() {
	for {
		select {
		case event := <-this.incoming:
			this.dispatch(event)

		}
	}
}

func (this *EventProcessor) dispatch(event user.IEventStruct) {
	var uuid string = event.GetUUID()
	found, eWorker := this.getWorkerByUUID(uuid)
	if !found {
		// TODO ADD a new eventWorker into queue
	}

	err := eWorker.Write(event)
	if err != nil {
		//...
	}
}

func (this *EventProcessor) Incoming() chan user.IEventStruct {
	return this.incoming
}

func (this EventProcessor) getWorkerByUUID(uuid string) (bool, IWorker) {
	var eWorker IWorker
	var found bool
	eWorker, found = this.workerQueue[uuid]
	if !found {
		return false, eWorker
	}
	return true, eWorker
}

// Write event
func (this *EventProcessor) Write(event user.IEventStruct) {
	select {
	case this.incoming <- event:
		return
	}
}
