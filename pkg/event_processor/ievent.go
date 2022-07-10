package event_processor

type EventType uint8

const (
	// EventTypeOutput upload to server or write to logfile.
	EventTypeOutput EventType = iota

	// EventTypeModuleData set as module cache data
	EventTypeModuleData

	// EventTypeEventProcessor display by event_processor.
	EventTypeEventProcessor
)

type IEventStruct interface {
	Decode(payload []byte) (err error)
	Payload() []byte
	PayloadLen() int
	String() string
	StringHex() string
	Clone() IEventStruct
	//Module() IModule
	//SetModule(IModule)
	EventType() EventType
	GetUUID() string
}
