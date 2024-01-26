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

package module

import (
	"bytes"
	"context"
	"crypto"
	"ecapture/assets"
	"ecapture/pkg/util/hkdf"
	"ecapture/user/config"
	"ecapture/user/event"
	"fmt"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ConnNotFound = "[ADDR_NOT_FOUND]"
	DefaultAddr  = "0.0.0.0"
)

type Tls13MasterSecret struct {
	ServerHandshakeTrafficSecret []byte
	ExporterSecret               []byte
	ServerTrafficSecret0         []byte
	ClientHandshakeTrafficSecret []byte
	ClientTrafficSecret0         []byte
}

type TlsCaptureModelType uint8

const (
	TlsCaptureModelTypePcap TlsCaptureModelType = iota
	TlsCaptureModelTypeText
	TlsCaptureModelTypeKeylog
)

type MOpenSSLProbe struct {
	MTCProbe
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	// pid[fd:Addr]
	pidConns  map[uint32]map[uint32]string
	pidLocker sync.Locker

	keyloggerFilename string
	keylogger         *os.File
	masterKeys        map[string]bool
	eBPFProgramType   TlsCaptureModelType

	sslVersionBpfMap map[string]string // bpf map key: ssl version, value: bpf map key
	sslBpfFile       string            // ssl bpf file
	isBoringSSL      bool              //
	masterHookFunc   string            // SSL_in_init on boringSSL,  SSL_write on openssl
	cgroupPath       string
}

// 对象初始化
func (m *MOpenSSLProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	m.Module.Init(ctx, logger, conf)
	m.conf = conf
	m.Module.SetChild(m)
	m.eventMaps = make([]*ebpf.Map, 0, 2)
	m.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	m.pidConns = make(map[uint32]map[uint32]string)
	m.pidLocker = new(sync.Mutex)
	m.masterKeys = make(map[string]bool)
	m.sslVersionBpfMap = make(map[string]string)

	//fd := os.Getpid()
	var err error
	var model = m.conf.(*config.OpensslConfig).Model
	switch model {
	case config.TlsCaptureModelKeylog, config.TlsCaptureModelKey:
		m.keyloggerFilename = m.conf.(*config.OpensslConfig).KeylogFile
		m.keylogger, err = os.OpenFile(m.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
		m.eBPFProgramType = TlsCaptureModelTypeKeylog
		m.logger.Printf("%s\tmaster key keylogger: %s\n", m.Name(), m.keyloggerFilename)
	case config.TlsCaptureModelPcap, config.TlsCaptureModelPcapng:
		var pcapFile = m.conf.(*config.OpensslConfig).PcapFile
		m.eBPFProgramType = TlsCaptureModelTypePcap
		fileInfo, err := filepath.Abs(pcapFile)
		if err != nil {
			return err
		}
		m.tcPacketsChan = make(chan *TcPacket, 2048)
		m.tcPackets = make([]*TcPacket, 0, 256)
		m.pcapngFilename = fileInfo
	case config.TlsCaptureModelText:
		fallthrough
	default:
		m.eBPFProgramType = TlsCaptureModelTypeText
		m.logger.Printf("%s\tmaster key keylogger: %s\n", m.Name(), m.keyloggerFilename)
	}

	var ts unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return err
	}
	startTime := ts.Nano()
	// Calculate the boot time using the monotonic time (since m is the clock we're using as a timestamp)
	// Note: m is NOT the real boot time, as the monotonic clock doesn't take into account system sleeps.
	bootTime := time.Now().UnixNano() - startTime

	m.startTime = uint64(startTime)
	m.bootTime = uint64(bootTime)

	m.tcPacketLocker = &sync.Mutex{}
	m.masterKeyBuffer = bytes.NewBuffer([]byte{})

	m.initOpensslOffset()
	m.cgroupPath = m.conf.(*config.OpensslConfig).CGroupPath

	return nil
}

// getSslBpfFile 根据sslVersion参数，获取对应的bpf文件
func (m *MOpenSSLProbe) getSslBpfFile(soPath, sslVersion string) error {
	defer func() {
		if strings.Contains(m.sslBpfFile, "boringssl") {
			m.isBoringSSL = true
			m.masterHookFunc = MasterKeyHookFuncBoringSSL
		} else {
			m.masterHookFunc = MasterKeyHookFuncOpenSSL
		}
	}()

	if sslVersion != "" {
		m.logger.Printf("%s\tOpenSSL/BoringSSL version: %s\n", m.Name(), sslVersion)
		bpfFile, found := m.sslVersionBpfMap[sslVersion]
		if found {
			m.sslBpfFile = bpfFile
			return nil
		} else {
			m.logger.Printf("%s\tCan't found OpenSSL/BoringSSL bpf bytecode file. auto detected.\n", m.Name())
		}
	}

	// 未找到对应的bpf文件，尝试从so文件中获取
	err := m.detectOpenssl(soPath)
	return err
}

func (m *MOpenSSLProbe) Start() error {
	return m.start()
}

func (m *MOpenSSLProbe) start() error {

	var err error
	// setup the managers
	switch m.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		m.logger.Printf("%s\tKeylog MODEL\n", m.Name())
		err = m.setupManagersKeylog()
	case TlsCaptureModelTypePcap:
		m.logger.Printf("%s\tPcapng MODEL\n", m.Name())
		err = m.setupManagersPcap()
	case TlsCaptureModelTypeText:
		m.logger.Printf("%s\tText MODEL\n", m.Name())
		err = m.setupManagersText()
	default:
		m.logger.Printf("%s\tText MODEL\n", m.Name())
		err = m.setupManagersText()
	}
	if err != nil {
		return err
	}

	// fetch ebpf assets
	// user/bytecode/openssl_kern.o
	var bpfFileName = m.geteBPFName(filepath.Join("user/bytecode", m.sslBpfFile))
	m.logger.Printf("%s\tBPF bytecode filename:%s\n", m.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)

	if err != nil {
		return fmt.Errorf("%s\tcouldn't find asset %v .", m.Name(), err)
	}

	// initialize the bootstrap manager
	if err = m.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), m.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = m.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}

	// 加载map信息，map对应events decode表。
	switch m.eBPFProgramType {
	case TlsCaptureModelTypeKeylog:
		err = m.initDecodeFunKeylog()
	case TlsCaptureModelTypePcap:
		err = m.initDecodeFunPcap()
	case TlsCaptureModelTypeText:
		err = m.initDecodeFunText()
	default:
		err = m.initDecodeFunText()
	}
	if err != nil {
		return err
	}

	return nil
}

func (m *MOpenSSLProbe) Close() error {

	m.logger.Printf("%s\tclose. \n", m.Name())
	if err := m.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	return m.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (m *MOpenSSLProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(m.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(m.conf.GetUid()),
		},
		{
			Name:  "target_port",
			Value: uint64(m.conf.(*config.OpensslConfig).Port),
		},
	}

	if m.conf.GetPid() <= 0 {
		m.logger.Printf("%s\ttarget all process. \n", m.Name())
	} else {
		m.logger.Printf("%s\ttarget PID:%d \n", m.Name(), m.conf.GetPid())
	}

	if m.conf.GetUid() <= 0 {
		m.logger.Printf("%s\ttarget all users. \n", m.Name())
	} else {
		m.logger.Printf("%s\ttarget UID:%d \n", m.Name(), m.conf.GetUid())
	}

	return editor
}

func (m *MOpenSSLProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := m.eventFuncMaps[em]
	return fun, found
}

func (m *MOpenSSLProbe) Events() []*ebpf.Map {
	return m.eventMaps
}

func (m *MOpenSSLProbe) AddConn(pid, fd uint32, addr string) {
	if fd <= 0 {
		m.logger.Printf("%s\tAddConn failed. pid:%d, fd:%d, addr:%s\n", m.Name(), pid, fd, addr)
		return
	}
	// save
	var connMap map[uint32]string
	var f bool
	m.pidLocker.Lock()
	defer m.pidLocker.Unlock()
	connMap, f = m.pidConns[pid]
	if !f {
		connMap = make(map[uint32]string)
	}
	connMap[fd] = addr
	m.pidConns[pid] = connMap
	//m.logger.Printf("%s\tAddConn pid:%d, fd:%d, addr:%s, mapinfo:%v\n", m.Name(), pid, fd, addr, m.pidConns)
	return
}

// process exit :fd is 0 , delete all pid map
// fd exit :pid > 0, fd > 0, delete fd value
// TODO add fd * pid exit event hook
func (m *MOpenSSLProbe) DelConn(pid, fd uint32) {
	// delete from map
	if pid == 0 {
		return
	}
	m.pidLocker.Lock()
	defer m.pidLocker.Unlock()
	if fd == 0 {
		delete(m.pidConns, pid)
	}
	var connMap map[uint32]string
	var f bool
	connMap, f = m.pidConns[pid]
	if !f {
		return
	}
	delete(connMap, fd)
	m.pidConns[pid] = connMap
	return
}
func (m *MOpenSSLProbe) GetConn(pid, fd uint32) string {
	if fd <= 0 {
		return ConnNotFound
	}
	addr := ""
	var connMap map[uint32]string
	var f bool
	//m.logger.Printf("%s\tGetConn pid:%d, fd:%d, mapinfo:%v\n", m.Name(), pid, fd, m.pidConns)
	m.pidLocker.Lock()
	defer m.pidLocker.Unlock()
	connMap, f = m.pidConns[pid]
	if !f {
		return ConnNotFound
	}
	addr, f = connMap[fd]
	if !f {
		return ConnNotFound
	}
	return addr
}

func (m *MOpenSSLProbe) saveMasterSecret(secretEvent *event.MasterSecretEvent) {

	var k = fmt.Sprintf("%02x", secretEvent.ClientRandom)

	_, f := m.masterKeys[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}
	m.masterKeys[k] = true

	// save to file
	var b *bytes.Buffer
	switch secretEvent.Version {
	case event.Tls12Version:
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelTLS12, secretEvent.ClientRandom, secretEvent.MasterKey))
	case event.Tls13Version:
		var length int
		var transcript crypto.Hash
		switch uint16(secretEvent.CipherId & 0x0000FFFF) {
		case hkdf.TlsAes128GcmSha256, hkdf.TlsChacha20Poly1305Sha256:
			length = 32
			transcript = crypto.SHA256
		case hkdf.TlsAes256GcmSha384:
			length = 48
			transcript = crypto.SHA384
		default:
			m.logger.Printf("non-TLSv1.3 cipher suite found, CipherId: %d", secretEvent.CipherId)
			return
		}

		clientHandshakeSecret := hkdf.ExpandLabel(secretEvent.HandshakeSecret[:length],
			hkdf.ClientHandshakeTrafficLabel, secretEvent.HandshakeTrafficHash[:length], length, transcript)
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelClientHandshake, secretEvent.ClientRandom, clientHandshakeSecret))

		serverHandshakeSecret := hkdf.ExpandLabel(secretEvent.HandshakeSecret[:length],
			hkdf.ServerHandshakeTrafficLabel, secretEvent.HandshakeTrafficHash[:length], length, transcript)
		b.WriteString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelServerHandshake, secretEvent.ClientRandom, serverHandshakeSecret))

		b.WriteString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelClientTraffic, secretEvent.ClientRandom, secretEvent.ClientAppTrafficSecret))

		b.WriteString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelServerTraffic, secretEvent.ClientRandom, secretEvent.ServerAppTrafficSecret))

		b.WriteString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelExporterSecret, secretEvent.ClientRandom, secretEvent.ExporterMasterSecret[:length]))

	default:
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelTLS12, secretEvent.ClientRandom, secretEvent.MasterKey))
	}
	v := event.TlsVersion{Version: secretEvent.Version}

	//
	switch m.eBPFProgramType {
	case TlsCaptureModelTypePcap:
		e := m.savePcapngSslKeyLog(b.Bytes())
		if e != nil {
			m.logger.Fatalf("%s\t%s: save CLIENT_RANDOM to pcapng error:%s", m.Name(), v.String(), e.Error())
			return
		}
		m.logger.Printf("%s\t%s: save CLIENT_RANDOM %02x to file success, %d bytes", m.Name(), v.String(), secretEvent.ClientRandom, b.Len())
	case TlsCaptureModelTypeKeylog:
		l, e := m.keylogger.WriteString(b.String())
		if e != nil {
			m.logger.Fatalf("%s\t%s: save CLIENT_RANDOM to file error:%s", m.Name(), v.String(), e.Error())
			return
		}
		m.logger.Printf("%s\t%s: save CLIENT_RANDOM %02x to file success, %d bytes", m.Name(), v.String(), secretEvent.ClientRandom, l)
	default:
	}
}

func (m *MOpenSSLProbe) saveMasterSecretBSSL(secretEvent *event.MasterSecretBSSLEvent) {
	var k = fmt.Sprintf("%02x", secretEvent.ClientRandom)

	_, f := m.masterKeys[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}

	// save to file
	var b *bytes.Buffer
	switch secretEvent.Version {
	case event.Tls12Version:
		if m.bSSLEvent12NullSecrets(secretEvent) {
			return
		}
		var length = int(secretEvent.HashLen)
		if length > event.MasterSecretMaxLen {
			length = event.MasterSecretMaxLen
			m.logger.Printf("%s\tmaster secret length is too long, truncate to 48 bytes, but it may cause keylog file error\n", m.Name())
		}
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelTLS12, secretEvent.ClientRandom, secretEvent.Secret[:length]))
		m.masterKeys[k] = true
	case event.Tls13Version:
		fallthrough
	default:
		var length int
		length = int(secretEvent.HashLen)
		if length > event.EvpMaxMdSize {
			m.logger.Printf("%s\tmaster secret length is too long, truncate to 64 bytes, but it may cause keylog file error\n", m.Name())
			length = event.EvpMaxMdSize
		}
		// 判断 密钥是否为空
		if m.bSSLEvent13NullSecrets(secretEvent) {
			return
		}
		m.masterKeys[k] = true
		//m.logger.Printf("secretEvent.HashLen:%d, CipherId:%d", secretEvent.HashLen, secretEvent.HashLen)
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientHandshake, secretEvent.ClientRandom, secretEvent.ClientHandshakeSecret[:length]))
		//b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientEarlyTafficSecret, secretEvent.ClientRandom, secretEvent.EarlyTrafficSecret[:length]))
		b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientTraffic, secretEvent.ClientRandom, secretEvent.ClientTrafficSecret0[:length]))
		b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelServerHandshake, secretEvent.ClientRandom, secretEvent.ServerHandshakeSecret[:length]))
		b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelServerTraffic, secretEvent.ClientRandom, secretEvent.ServerTrafficSecret0[:length]))
		b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelExporterSecret, secretEvent.ClientRandom, secretEvent.ExporterSecret[:length]))
	}

	v := event.TlsVersion{Version: secretEvent.Version}
	//
	switch m.eBPFProgramType {
	case TlsCaptureModelTypePcap:
		e := m.savePcapngSslKeyLog(b.Bytes())
		if e != nil {
			m.logger.Fatalf("%s\t%s: save CLIENT_RANDOM to pcapng error:%s", m.Name(), v.String(), e.Error())
			return
		}
		m.logger.Printf("%s\t%s: save CLIENT_RANDOM %02x to file success, %d bytes", m.Name(), v.String(), secretEvent.ClientRandom, b.Len())
	case TlsCaptureModelTypeKeylog:
		l, e := m.keylogger.WriteString(b.String())
		if e != nil {
			m.logger.Fatalf("%s\t%s: save CLIENT_RANDOM to file error:%s", m.Name(), v.String(), e.Error())
			return
		}
		m.logger.Printf("%s\t%s: save CLIENT_RANDOM %02x to file success, %d bytes", m.Name(), v.String(), secretEvent.ClientRandom, l)
	default:
	}
}

func (m *MOpenSSLProbe) bSSLEvent12NullSecrets(e *event.MasterSecretBSSLEvent) bool {
	var isNull = true
	var hashLen = int(e.HashLen)
	for i := 0; i < hashLen; i++ {
		if hashLen >= len(e.Secret) {
			break
		}
		if e.Secret[i] != 0 {
			isNull = false
			break
		}
	}
	return isNull
}

func (m *MOpenSSLProbe) bSSLEvent13NullSecrets(e *event.MasterSecretBSSLEvent) bool {
	var isNUllCount = 5

	var hashLen = int(e.HashLen)
	var chsChecked, ctsChecked, shsChecked, stsChecked, esChecked bool
	for i := 0; i < hashLen; i++ {
		if !chsChecked && e.ClientHandshakeSecret[i] != 0 {
			isNUllCount -= 1
			chsChecked = true
		}

		if !ctsChecked && e.ClientTrafficSecret0[i] != 0 {
			isNUllCount -= 1
			ctsChecked = true
		}

		if !shsChecked && e.ServerHandshakeSecret[i] != 0 {
			isNUllCount -= 1
			shsChecked = true
		}

		if !stsChecked && e.ServerTrafficSecret0[i] != 0 {
			isNUllCount -= 1
			stsChecked = true
		}

		if !esChecked && e.ExporterSecret[i] != 0 {
			isNUllCount -= 1
			esChecked = true
		}
	}
	return isNUllCount != 0
}

func (m *MOpenSSLProbe) Dispatcher(eventStruct event.IEventStruct) {
	// detect eventStruct type
	switch eventStruct.(type) {
	case *event.ConnDataEvent:
		m.AddConn(eventStruct.(*event.ConnDataEvent).Pid, eventStruct.(*event.ConnDataEvent).Fd, eventStruct.(*event.ConnDataEvent).Addr)
	case *event.MasterSecretEvent:
		m.saveMasterSecret(eventStruct.(*event.MasterSecretEvent))
	case *event.MasterSecretBSSLEvent:
		m.saveMasterSecretBSSL(eventStruct.(*event.MasterSecretBSSLEvent))
	case *event.TcSkbEvent:
		err := m.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
		if err != nil {
			m.logger.Printf("%s\t save packet error %s .\n", m.Name(), err.Error())
		}
	case *event.SSLDataEvent:
		m.dumpSslData(eventStruct.(*event.SSLDataEvent))
	}
	//m.logger.Println(eventStruct)
}

func (m *MOpenSSLProbe) dumpSslData(eventStruct *event.SSLDataEvent) {
	if eventStruct.Fd <= 0 {
		m.logger.Printf("\tnotice: SSLDataEvent's fd is 0.  pid:%d, fd:%d, addr:%s\n", eventStruct.Pid, eventStruct.Fd, eventStruct.Addr)
	}
	var addr = m.GetConn(eventStruct.Pid, eventStruct.Fd)
	//m.logger.Printf("\tSSLDataEvent pid:%d, fd:%d, addr:%s\n", eventStruct.Pid, eventStruct.Fd, addr)
	if addr == ConnNotFound {
		eventStruct.Addr = DefaultAddr
	} else {
		eventStruct.Addr = addr
	}
	//m.processor.PcapFile(eventStruct)
	if m.conf.GetHex() {
		m.logger.Println(eventStruct.StringHex())
	} else {
		m.logger.Println(eventStruct.String())
	}
}

func init() {
	mod := &MOpenSSLProbe{}
	mod.name = ModuleNameOpenssl
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
