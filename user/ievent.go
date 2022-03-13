package user

type IEventStruct interface {
	Decode(payload []byte) (err error)
	String() string
	Clone() IEventStruct
}
