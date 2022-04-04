package user

type IEventStruct interface {
	Decode(payload []byte) (err error)
	String() string
	StringHex() string
	Clone() IEventStruct
	Module() IModule
	SetModule(IModule)
}
