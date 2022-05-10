package user

type EVENT_TYPE uint8

const (
	// upload to server or write to logfile.
	EVENT_TYPE_OUTPUT EVENT_TYPE = iota

	// set as module cache data
	EVENT_TYPE_MODULE_DATA
)

type IEventStruct interface {
	Decode(payload []byte) (err error)
	String() string
	StringHex() string
	Clone() IEventStruct
	Module() IModule
	SetModule(IModule)
	EventType() EVENT_TYPE
}
