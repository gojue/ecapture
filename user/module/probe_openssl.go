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
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ConnNotFound = "[ADDR_NOT_FOUND]"
)

type Tls13MasterSecret struct {
	ServerHandshakeTrafficSecret []byte
	ExporterSecret               []byte
	ServerTrafficSecret0         []byte
	ClientHandshakeTrafficSecret []byte
	ClientTrafficSecret0         []byte
}

type EBPFPROGRAMTYPE uint8

const (
	EbpfprogramtypeOpensslTc EBPFPROGRAMTYPE = iota
	EbpfprogramtypeOpensslUprobe
)

type MOpenSSLProbe struct {
	Module
	MTCProbe
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	// pid[fd:Addr]
	//pidConns map[uint32]map[uint32]string

	keyloggerFilename string
	keylogger         *os.File
	masterKeys        map[string]bool
	eBPFProgramType   EBPFPROGRAMTYPE

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
	//m.pidConns = make(map[uint32]map[uint32]string)
	m.masterKeys = make(map[string]bool)
	m.sslVersionBpfMap = make(map[string]string)

	//fd := os.Getpid()
	m.keyloggerFilename = MasterSecretKeyLogName
	file, err := os.OpenFile(m.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	m.keylogger = file
	var writeFile = m.conf.(*config.OpensslConfig).Write
	if len(writeFile) > 0 {
		m.eBPFProgramType = EbpfprogramtypeOpensslTc
		fileInfo, err := filepath.Abs(writeFile)
		if err != nil {
			return err
		}
		m.pcapngFilename = fileInfo
	} else {
		m.eBPFProgramType = EbpfprogramtypeOpensslUprobe
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

	m.tcPackets = make([]*TcPacket, 0, 1024)
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
	case EbpfprogramtypeOpensslTc:
		m.logger.Printf("%s\tTC MODEL\n", m.Name())
		err = m.setupManagersTC()
	case EbpfprogramtypeOpensslUprobe:
		m.logger.Printf("%s\tUPROBE MODEL\n", m.Name())
		err = m.setupManagersUprobe()
	default:
		m.logger.Printf("%s\tUPROBE MODEL\n", m.Name())
		err = m.setupManagersUprobe()
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
	case EbpfprogramtypeOpensslTc:
		err = m.initDecodeFunTC()
	case EbpfprogramtypeOpensslUprobe:
		err = m.initDecodeFun()
	default:
		err = m.initDecodeFun()
	}
	if err != nil {
		return err
	}

	return nil
}

func (m *MOpenSSLProbe) Close() error {
	if m.eBPFProgramType == EbpfprogramtypeOpensslTc {
		m.logger.Printf("%s\tsaving pcapng file %s\n", m.Name(), m.pcapngFilename)
		i, err := m.savePcapng()
		if err != nil {
			m.logger.Printf("%s\tsave pcanNP failed, error:%v. \n", m.Name(), err)
		}
		if i == 0 {
			m.logger.Printf("nothing captured, please check your network interface, see \"ecapture tls -h\" for more information.")
		} else {
			m.logger.Printf("%s\t save %d packets into pcapng file.\n", m.Name(), i)
		}
	}

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

func (m *MOpenSSLProbe) setupManagersUprobe() error {
	var binaryPath, sslVersion string
	sslVersion = m.conf.(*config.OpensslConfig).SslVersion
	sslVersion = strings.ToLower(sslVersion)
	switch m.conf.(*config.OpensslConfig).ElfType {
	case config.ElfTypeBin:
		binaryPath = m.conf.(*config.OpensslConfig).Curlpath
	case config.ElfTypeSo:
		binaryPath = m.conf.(*config.OpensslConfig).Openssl
		err := m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libssl.so.1.1"
		err := m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	m.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", m.Name(), m.conf.(*config.OpensslConfig).ElfType, binaryPath)
	m.logger.Printf("%s\tHook masterKey function:%s\n", m.Name(), m.masterHookFunc)

	m.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{

			{
				Section:          "uprobe/SSL_write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/SSL_write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uprobe/SSL_read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/SSL_read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       binaryPath,
			},

			// --------------------------------------------------
			/*
				{
					Section:          "uprobe/connect",
					EbpfFuncName:     "probe_connect",
					AttachToFuncName: "connect",
					BinaryPath:       libPthread,
				},
			*/
			// --------------------------------------------------

			// openssl masterkey
			{
				Section:          "uprobe/SSL_write_key",
				EbpfFuncName:     "probe_ssl_master_key",
				AttachToFuncName: m.masterHookFunc,
				BinaryPath:       binaryPath,
				UID:              "uprobe_ssl_master_key",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "tls_events",
			},
			{
				Name: "connect_events",
			},
			{
				Name: "mastersecret_events",
			},
		},
	}

	m.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if m.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		m.bpfManagerOptions.ConstantEditors = m.constantEditor()
	}
	return nil
}

func (m *MOpenSSLProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := m.eventFuncMaps[em]
	return fun, found
}

func (m *MOpenSSLProbe) initDecodeFun() error {
	//SSLDumpEventsMap 与解码函数映射
	SSLDumpEventsMap, found, err := m.bpfManager.GetMap("tls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tls_events")
	}
	m.eventMaps = append(m.eventMaps, SSLDumpEventsMap)
	sslEvent := &event.SSLDataEvent{}
	//sslEvent.SetModule(m)
	m.eventFuncMaps[SSLDumpEventsMap] = sslEvent

	ConnEventsMap, found, err := m.bpfManager.GetMap("connect_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:connect_events")
	}
	m.eventMaps = append(m.eventMaps, ConnEventsMap)
	connEvent := &event.ConnDataEvent{}
	//connEvent.SetModule(m)
	m.eventFuncMaps[ConnEventsMap] = connEvent

	MasterkeyEventsMap, found, err := m.bpfManager.GetMap("mastersecret_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	m.eventMaps = append(m.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	if m.isBoringSSL {
		masterkeyEvent = &event.MasterSecretBSSLEvent{}
	} else {
		masterkeyEvent = &event.MasterSecretEvent{}
	}
	//masterkeyEvent.SetModule(m)
	m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent

	return nil
}

func (m *MOpenSSLProbe) Events() []*ebpf.Map {
	return m.eventMaps
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
	l, e := m.keylogger.WriteString(b.String())
	if e != nil {
		m.logger.Fatalf("%s: save CLIENT_RANDOM to file error:%s", v.String(), e.Error())
		return
	}

	//
	switch m.eBPFProgramType {
	case EbpfprogramtypeOpensslTc:
		e = m.savePcapngSslKeyLog(b.Bytes())
		if e != nil {
			m.logger.Fatalf("%s: save CLIENT_RANDOM to pcapng error:%s", v.String(), e.Error())
			return
		}
	default:
	}
	m.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", v.String(), secretEvent.ClientRandom, l)
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
			m.logger.Println("master secret length is too long, truncate to 48 bytes, but it may cause keylog file error")
		}
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelTLS12, secretEvent.ClientRandom, secretEvent.Secret[:length]))
		m.masterKeys[k] = true
	case event.Tls13Version:
		fallthrough
	default:
		var length int
		length = int(secretEvent.HashLen)
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
	l, e := m.keylogger.WriteString(b.String())
	if e != nil {
		m.logger.Fatalf("%s: save CLIENT_RANDOM to file error:%s", v.String(), e.Error())
		return
	}

	//
	switch m.eBPFProgramType {
	case EbpfprogramtypeOpensslTc:
		m.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", v.String(), secretEvent.ClientRandom, l)
		e = m.savePcapngSslKeyLog(b.Bytes())
		if e != nil {
			m.logger.Fatalf("%s: save CLIENT_RANDOM to pcapng error:%s", v.String(), e.Error())
			return
		}
	default:
		m.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", v.String(), secretEvent.ClientRandom, l)
	}
}

func (m *MOpenSSLProbe) bSSLEvent12NullSecrets(e *event.MasterSecretBSSLEvent) bool {
	var isNull = true
	var hashLen = int(e.HashLen)
	for i := 0; i < hashLen; i++ {
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
		//m.AddConn(eventStruct.(*event.ConnDataEvent).Pid, eventStruct.(*event.ConnDataEvent).Fd, eventStruct.(*event.ConnDataEvent).Addr)
	case *event.MasterSecretEvent:
		m.saveMasterSecret(eventStruct.(*event.MasterSecretEvent))
	case *event.MasterSecretBSSLEvent:
		m.saveMasterSecretBSSL(eventStruct.(*event.MasterSecretBSSLEvent))
	case *event.TcSkbEvent:
		err := m.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
		if err != nil {
			m.logger.Printf("%s\t save packet error %s .\n", m.Name(), err.Error())
		}
	}
	//m.logger.Println(eventStruct)
}

func init() {
	mod := &MOpenSSLProbe{}
	mod.name = ModuleNameOpenssl
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
