package handlers

import (
	"fmt"
	"io"
	"sync"

	"github.com/gojue/ecapture/internal/domain"
)

const (
	Ssl3RandomSize     = 32
	MasterSecretMaxLen = 48
	EvpMaxMdSize       = 64
)

const (
	keyLogLabelTLS12           = "CLIENT_RANDOM"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
	keyLogLabelExporterSecret  = "EXPORTER_SECRET"
)

// MasterSecretEvent is implemented by OpenSSL-style master secret events.
type MasterSecretEvent interface {
	domain.Event
	GetVersion() int32
	GetClientRandom() []byte
	GetMasterKey() []byte
	GetHandshakeSecret() []byte
	GetClientAppTrafficSecret() []byte
	GetServerAppTrafficSecret() []byte
	GetExporterMasterSecret() []byte
}

// GoTLSMasterSecretEvent is implemented by GoTLS-style (label-based) master secret events.
type GoTLSMasterSecretEvent interface {
	domain.Event
	GetLabel() string
	GetClientRandom() []byte
	GetSecret() []byte
}

// KeylogEncoder writes TLS master secrets in NSS Key Log Format.
type KeylogEncoder struct {
	writer   io.Writer
	mu       sync.Mutex
	seenKeys map[string]bool
}

func NewKeylogEncoder(w io.Writer) *KeylogEncoder {
	return &KeylogEncoder{
		writer:   w,
		seenKeys: make(map[string]bool),
	}
}

func (e *KeylogEncoder) Encode(event domain.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if goEvent, ok := event.(GoTLSMasterSecretEvent); ok {
		return e.writeGoTLS(goEvent)
	}
	if msEvent, ok := event.(MasterSecretEvent); ok {
		if msEvent.GetVersion() <= 0x0303 {
			return e.writeTLS12(msEvent)
		}
		return e.writeTLS13(msEvent)
	}
	return nil // not a key event, silently skip
}

func (e *KeylogEncoder) Name() string { return "keylog" }

func (e *KeylogEncoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seenKeys = make(map[string]bool)
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (e *KeylogEncoder) writeTLS12(event MasterSecretEvent) error {
	cr := event.GetClientRandom()
	mk := event.GetMasterKey()
	if len(cr) < Ssl3RandomSize || len(mk) < MasterSecretMaxLen {
		return nil
	}
	if isZero(mk[:MasterSecretMaxLen]) {
		return nil
	}
	k := fmt.Sprintf("%s_%x", keyLogLabelTLS12, cr[:Ssl3RandomSize])
	if e.seenKeys[k] {
		return nil
	}
	e.seenKeys[k] = true
	_, err := fmt.Fprintf(e.writer, "%s %x %x\n", keyLogLabelTLS12, cr[:Ssl3RandomSize], mk[:MasterSecretMaxLen])
	return err
}

func (e *KeylogEncoder) writeTLS13(event MasterSecretEvent) error {
	cr := event.GetClientRandom()
	if len(cr) < Ssl3RandomSize {
		return nil
	}
	hex := fmt.Sprintf("%x", cr[:Ssl3RandomSize])
	secrets := []struct {
		label string
		data  []byte
	}{
		{keyLogLabelClientTraffic, event.GetClientAppTrafficSecret()},
		{keyLogLabelServerTraffic, event.GetServerAppTrafficSecret()},
		{keyLogLabelExporterSecret, event.GetExporterMasterSecret()},
		{keyLogLabelServerHandshake, event.GetHandshakeSecret()},
	}
	for _, s := range secrets {
		if len(s.data) == 0 || isZero(s.data) {
			continue
		}
		k := fmt.Sprintf("%s_%s", s.label, hex)
		if e.seenKeys[k] {
			continue
		}
		e.seenKeys[k] = true
		if _, err := fmt.Fprintf(e.writer, "%s %s %x\n", s.label, hex, s.data); err != nil {
			return err
		}
	}
	return nil
}

func (e *KeylogEncoder) writeGoTLS(event GoTLSMasterSecretEvent) error {
	label, cr, secret := event.GetLabel(), event.GetClientRandom(), event.GetSecret()
	if label == "" || len(cr) == 0 || len(secret) == 0 {
		return nil
	}
	if isZero(secret) {
		return nil
	}
	k := fmt.Sprintf("%s_%x", label, cr)
	if e.seenKeys[k] {
		return nil
	}
	e.seenKeys[k] = true
	_, err := fmt.Fprintf(e.writer, "%s %x %x\n", label, cr, secret)
	return err
}

func isZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
