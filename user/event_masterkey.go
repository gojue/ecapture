package user

import (
	"bytes"
	"ecapture/pkg/event_processor"
	"encoding/binary"
	"fmt"
)

// openssl_masterkey_events

const (
	SSL3_RANDOM_SIZE      = 32
	MASTER_SECRET_MAX_LEN = 48
)

/*
	u8 client_random[SSL3_RANDOM_SIZE];
    u8 master_key[MASTER_SECRET_MAX_LEN];
*/
type MasterKeyEvent struct {
	module       IModule
	event_type   event_processor.EventType
	ClientRandom [SSL3_RANDOM_SIZE]byte
	MasterKey    [MASTER_SECRET_MAX_LEN]byte
	payload      string
}

func (this *MasterKeyEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &this.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &this.MasterKey); err != nil {
		return
	}
	this.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", this.ClientRandom, this.MasterKey)
	return nil
}

func (this *MasterKeyEvent) StringHex() string {
	s := fmt.Sprintf("ClientRandom:%02x, MasterKey:%02x", this.ClientRandom, this.MasterKey)
	return s
}

func (this *MasterKeyEvent) String() string {
	s := fmt.Sprintf("ClientRandom:%02x, MasterKey:%02x", this.ClientRandom, this.MasterKey)
	return s
}

func (this *MasterKeyEvent) SetModule(module IModule) {
	this.module = module
}

func (this *MasterKeyEvent) Module() IModule {
	return this.module
}

func (this *MasterKeyEvent) Clone() event_processor.IEventStruct {
	event := new(MasterKeyEvent)
	event.module = this.module
	event.event_type = event_processor.EventTypeModuleData
	return event
}

func (this *MasterKeyEvent) EventType() event_processor.EventType {
	return this.event_type
}

func (this *MasterKeyEvent) GetUUID() string {
	return fmt.Sprintf("%02X", this.ClientRandom)
}

func (this *MasterKeyEvent) Payload() []byte {
	return []byte(this.payload)
}

func (this *MasterKeyEvent) PayloadLen() int {
	return len(this.payload)
}
