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
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/pkg/util/hkdf"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

const (
	ConnNotFound = "[ADDR_NOT_FOUND]"
	DefaultAddr  = "0.0.0.0"
	// OpenSSL the classes of BIOs
	// https://github.com/openssl/openssl/blob/openssl-3.0.0/include/openssl/bio.h.in
	BIO_TYPE_DESCRIPTOR  = 0x0100
	BIO_TYPE_SOURCE_SINK = 0x0400
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

func (t TlsCaptureModelType) String() string {
	switch t {
	case TlsCaptureModelTypePcap:
		return "PcapNG"
	case TlsCaptureModelTypeKeylog:
		return "KeyLog"
	case TlsCaptureModelTypeText:
		return "Text"
	}
	return "UnknowTlsCaptureModel"
}

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
	masterHookFuncs  []string          // set by masterKeyHookFuncs
	cgroupPath       string
}

// 对象初始化
func (m *MOpenSSLProbe) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, ecw io.Writer) error {
	var err error
	err = m.Module.Init(ctx, logger, conf, ecw)
	if err != nil {
		return err
	}
	m.conf = conf
	m.Module.SetChild(m)
	m.eventMaps = make([]*ebpf.Map, 0, 2)
	m.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	m.pidConns = make(map[uint32]map[uint32]string)
	m.pidLocker = new(sync.Mutex)
	m.masterKeys = make(map[string]bool)
	m.sslVersionBpfMap = make(map[string]string)
	m.masterHookFuncs = masterKeyHookFuncs

	// fd := os.Getpid()
	model := m.conf.(*config.OpensslConfig).Model
	switch model {
	case config.TlsCaptureModelKeylog, config.TlsCaptureModelKey:
		m.keyloggerFilename = m.conf.(*config.OpensslConfig).KeylogFile
		m.keylogger, err = os.OpenFile(m.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		m.eBPFProgramType = TlsCaptureModelTypeKeylog
		m.logger.Info().Str("keylogger", m.keyloggerFilename).Str("eBPFProgramType", m.eBPFProgramType.String()).Msg("master key keylogger has been set.")
	case config.TlsCaptureModelPcap, config.TlsCaptureModelPcapng:
		pcapFile := m.conf.(*config.OpensslConfig).PcapFile
		m.eBPFProgramType = TlsCaptureModelTypePcap
		var fileInfo string
		fileInfo, err = filepath.Abs(pcapFile)
		if err != nil {
			m.logger.Warn().Err(err).Str("pcapFile", pcapFile).Str("eBPFProgramType", m.eBPFProgramType.String()).Msg("pcapFile not found")
			return err
		}
		m.tcPacketsChan = make(chan *TcPacket, 2048)
		m.tcPackets = make([]*TcPacket, 0, 256)
		m.pcapngFilename = fileInfo
	case config.TlsCaptureModelText:
		fallthrough
	default:
		m.eBPFProgramType = TlsCaptureModelTypeText
		m.logger.Info().Str("keylogger", m.keyloggerFilename).Str("eBPFProgramType", m.eBPFProgramType.String()).Msg("master key keylogger has been set.")
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
			m.masterHookFuncs = []string{MasterKeyHookFuncBoringSSL}
		}
		// TODO detect sslVersion less then 1.1.0 ,  ref # https://github.com/gojue/ecapture/issues/518
		tmpSslVer := m.conf.(*config.OpensslConfig).SslVersion
		if strings.Contains(tmpSslVer, " 1.0.") {
			// no function named SSL_in_before at openssl 1.0.* , and it is a macro definition， so need to change to SSL_state
			for i, hookFunc := range m.masterHookFuncs {
				if hookFunc == MasterKeyHookFuncSSLBefore {
					m.masterHookFuncs[i] = MasterKeyHookFuncSSLState
					m.logger.Info().Str("openssl version", tmpSslVer).Str("hookFunc", MasterKeyHookFuncSSLState).Str("oldHookFunc", MasterKeyHookFuncSSLBefore).Msg("openssl version is less than 1.0.*")
				}
			}
		}
	}()

	if sslVersion != "" {
		m.logger.Info().Str("sslVersion", sslVersion).Msg("OpenSSL/BoringSSL version found")
		bpfFile, found := m.sslVersionBpfMap[sslVersion]
		if found {
			m.sslBpfFile = bpfFile
			return nil
		} else {
			m.logger.Error().Msg("Can't found OpenSSL/BoringSSL bpf bytecode file. auto detected.")
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
		err = m.setupManagersKeylog()
	case TlsCaptureModelTypePcap:
		err = m.setupManagersPcap()
	case TlsCaptureModelTypeText:
		err = m.setupManagersText()
	default:
		err = m.setupManagersText()
	}
	m.logger.Info().Str("eBPFProgramType", m.eBPFProgramType.String()).Msg("setupManagers")
	if err != nil {
		return err
	}

	pcapFilter := m.conf.(*config.OpensslConfig).PcapFilter
	if m.eBPFProgramType == TlsCaptureModelTypePcap && pcapFilter != "" {
		ebpfFuncs := []string{tcFuncNameIngress, tcFuncNameEgress}
		m.bpfManager.InstructionPatchers = prepareInsnPatchers(m.bpfManager,
			ebpfFuncs, pcapFilter)
	}

	// fetch ebpf assets
	// user/bytecode/openssl_kern.o
	bpfFileName := m.geteBPFName(filepath.Join("user/bytecode", m.sslBpfFile))
	m.logger.Info().Str("bpfFileName", bpfFileName).Msg("BPF bytecode file is matched.")
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		m.logger.Error().Err(err).Strs("bytecode files", assets.AssetNames()).Msg("couldn't find bpf bytecode file")
		return fmt.Errorf("%s\tcouldn't find asset %v .", m.Name(), err)
	}

	// initialize the bootstrap manager
	if err = m.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), m.bpfManagerOptions); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			m.logger.Error().Err(ve).Msg("couldn't verify bpf prog")
		}
		return fmt.Errorf("couldn't init manager xxx %v", err)
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
		m.logger.Warn().Err(err).Msg("initDecodeFunText failed")
		return err
	}

	return nil
}

func (m *MOpenSSLProbe) Close() error {
	m.logger.Info().Msg("module close.")
	if err := m.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	return m.Module.Close()
}

// 通过elf的常量替换方式传递数据
func (m *MOpenSSLProbe) constantEditor() []manager.ConstantEditor {
	editor := []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(m.conf.GetPid()),
			// FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(m.conf.GetUid()),
		},
	}

	if m.conf.GetPid() <= 0 {
		m.logger.Info().Msg("target all process.")
	} else {
		m.logger.Info().Uint64("target PID", m.conf.GetPid()).Msg("target process.")
	}

	if m.conf.GetUid() <= 0 {
		m.logger.Info().Msg("target all users.")
	} else {
		m.logger.Info().Uint64("target UID", m.conf.GetUid()).Msg("target user.")
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
		m.logger.Info().Uint32("pid", pid).Uint32("fd", fd).Str("address", addr).Msg("AddConn failed")
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
	m.logger.Debug().Uint32("pid", pid).Uint32("fd", fd).Str("address", addr).Msg("AddConn success")
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
	m.logger.Debug().Uint32("pid", pid).Uint32("fd", fd).Msg("GetConn")
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
	k := fmt.Sprintf("%02x", secretEvent.ClientRandom)

	_, f := m.masterKeys[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}

	// save to file
	var b = bytes.NewBuffer(nil)
	switch secretEvent.Version {
	case event.Tls12Version:
		length := event.MasterSecretMaxLen
		if m.oSSLEvent12NullSecrets(length, secretEvent) {
			return
		}
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelTLS12, secretEvent.ClientRandom, secretEvent.MasterKey))
		m.masterKeys[k] = true
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
			length = 32
			transcript = crypto.SHA256
			m.logger.Info().Uint32("CipherId", secretEvent.CipherId).Str("CLientRandom", fmt.Sprintf("%02x", secretEvent.ClientRandom)).Msg("non-TLSv1.3 cipher suite found")
			return
		}

		clientHandshakeSecret := hkdf.ExpandLabel(secretEvent.HandshakeSecret[:length],
			hkdf.ClientHandshakeTrafficLabel, secretEvent.HandshakeTrafficHash[:length], length, transcript)
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelClientHandshake, secretEvent.ClientRandom, clientHandshakeSecret))

		serverHandshakeSecret := hkdf.ExpandLabel(secretEvent.HandshakeSecret[:length],
			hkdf.ServerHandshakeTrafficLabel, secretEvent.HandshakeTrafficHash[:length], length, transcript)

		var clientHandshakeSecret1, serverHandshakeSecret1 [64]byte
		copy(clientHandshakeSecret1[:length], clientHandshakeSecret)
		copy(serverHandshakeSecret1[:length], serverHandshakeSecret)
		// 判断 密钥是否为空
		if m.oSSLEvent13NullSecrets(length, secretEvent, clientHandshakeSecret1, serverHandshakeSecret1) {
			return
		}
		m.masterKeys[k] = true

		b.WriteString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelServerHandshake, secretEvent.ClientRandom, serverHandshakeSecret))

		b.WriteString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelClientTraffic, secretEvent.ClientRandom, secretEvent.ClientAppTrafficSecret[:length]))

		b.WriteString(fmt.Sprintf("%s %02x %02x\n",
			hkdf.KeyLogLabelServerTraffic, secretEvent.ClientRandom, secretEvent.ServerAppTrafficSecret[:length]))

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
			m.logger.Warn().Err(e).Str("TlsVersion", v.String()).Str("CLientRandom", k).Str("eBPFProgramType", m.eBPFProgramType.String()).Msg("CLIENT_RANDOM save failed")
			return
		}
		m.logger.Info().Str("TlsVersion", v.String()).Str("CLientRandom", k).Int("bytes", b.Len()).Msg("CLIENT_RANDOM save success")
	case TlsCaptureModelTypeKeylog:
		l, e := m.keylogger.WriteString(b.String())
		if e != nil {
			m.logger.Warn().Err(e).Str("TlsVersion", v.String()).Str("CLientRandom", k).Str("eBPFProgramType", m.eBPFProgramType.String()).Msg("CLIENT_RANDOM save failed")
			return
		}
		m.logger.Info().Str("TlsVersion", v.String()).Str("CLientRandom", k).Str("eBPFProgramType", m.eBPFProgramType.String()).Int("bytes", l).Msg("CLIENT_RANDOM save success")
	default:
	}
}

func (m *MOpenSSLProbe) saveMasterSecretBSSL(secretEvent *event.MasterSecretBSSLEvent) {
	k := fmt.Sprintf("%02x", secretEvent.ClientRandom)

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
		length := int(secretEvent.HashLen)
		if length > event.MasterSecretMaxLen {
			m.logger.Error().Int("length", length).Msg("master secret length is too long, truncate to 48 bytes, but it may cause keylog file error")
			length = event.MasterSecretMaxLen
		}
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelTLS12, secretEvent.ClientRandom, secretEvent.Secret[:length]))
		m.masterKeys[k] = true
	case event.Tls13Version:
		fallthrough
	default:
		var length int
		length = int(secretEvent.HashLen)
		if length > event.EvpMaxMdSize {
			m.logger.Error().Int("length", length).Msg("master secret length is too long, truncate to 64 bytes, but it may cause keylog file error")
			length = event.EvpMaxMdSize
		}
		// 判断 密钥是否为空
		if m.bSSLEvent13NullSecrets(secretEvent) {
			m.logger.Debug().Str("ClientRandom", k).Msg("something in mastersecret is null")
			return
		}
		m.masterKeys[k] = true
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientHandshake, secretEvent.ClientRandom, secretEvent.ClientHandshakeSecret[:length]))
		// b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientEarlyTafficSecret, secretEvent.ClientRandom, secretEvent.EarlyTrafficSecret[:length]))
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
			m.logger.Warn().Err(e).Str("eBPFProgramType", m.eBPFProgramType.String()).Str("CLientRandom", k).Msg("save sslKeylog failed")
			return
		}
		m.logger.Info().Str("eBPFProgramType", m.eBPFProgramType.String()).Str("sslVersion", v.String()).Str("CLientRandom", k).Int("bytes", b.Len()).Msg("CLIENT_RANDOM save success")
	case TlsCaptureModelTypeKeylog:
		l, e := m.keylogger.WriteString(b.String())
		if e != nil {
			m.logger.Warn().Err(e).Str("eBPFProgramType", m.eBPFProgramType.String()).Str("CLientRandom", k).Msg("save sslKeylog failed")
			return
		}
		m.logger.Info().Str("eBPFProgramType", m.eBPFProgramType.String()).Str("sslVersion", v.String()).Str("CLientRandom", k).Int("bytes", l).Msg("CLIENT_RANDOM save success")
	default:
	}
}

func (m *MOpenSSLProbe) bSSLEvent12NullSecrets(e *event.MasterSecretBSSLEvent) bool {
	return m.mk12NullSecrets(int(e.HashLen), e.Secret)
}

func (m *MOpenSSLProbe) oSSLEvent12NullSecrets(hashLen int, e *event.MasterSecretEvent) bool {
	return m.mk12NullSecrets(hashLen, e.MasterKey)
}

func (m *MOpenSSLProbe) mk12NullSecrets(hashLen int, secret [48]byte) bool {
	isNull := true
	for i := 0; i < hashLen; i++ {
		if hashLen > len(secret) {
			break
		}
		if secret[i] != 0 {
			isNull = false
			break
		}
	}
	return isNull
}

// bSSLEvent13NullSecrets 检测boringssl Secret Event 是不是空密钥
func (m *MOpenSSLProbe) bSSLEvent13NullSecrets(e *event.MasterSecretBSSLEvent) bool {
	hashLen := int(e.HashLen)
	return m.mk13NullSecrets(hashLen,
		e.ClientHandshakeSecret,
		e.ClientTrafficSecret0,
		e.ServerHandshakeSecret,
		e.ServerTrafficSecret0,
		e.ExporterSecret,
	)
}

// oSSLEvent13NullSecrets 检测openssl Secret Event 是不是空密钥
func (m *MOpenSSLProbe) oSSLEvent13NullSecrets(hashLen int, e *event.MasterSecretEvent, ClientHandshakeSecret, ServerHandshakeSecret [64]byte) bool {
	return m.mk13NullSecrets(hashLen,
		ClientHandshakeSecret,
		e.ClientAppTrafficSecret,
		ServerHandshakeSecret,
		e.ServerAppTrafficSecret,
		e.ExporterMasterSecret,
	)
}

func (m *MOpenSSLProbe) mk13NullSecrets(hashLen int,
	ClientHandshakeSecret [64]byte,
	ClientTrafficSecret0 [64]byte,
	ServerHandshakeSecret [64]byte,
	ServerTrafficSecret0 [64]byte,
	ExporterSecret [64]byte,
) bool {
	isNUllCount := 5

	// The mandatory setting is 64 bytes, and the length of the XXXX secret is not allowed to be more than 64 bytes.
	if hashLen > 64 {
		hashLen = 64
	}

	var chsChecked, ctsChecked, shsChecked, stsChecked, esChecked bool
	for i := 0; i < hashLen; i++ {
		if !chsChecked && ClientHandshakeSecret[i] != 0 {
			isNUllCount -= 1
			chsChecked = true
		}

		if !ctsChecked && ClientTrafficSecret0[i] != 0 {
			isNUllCount -= 1
			ctsChecked = true
		}

		if !shsChecked && ServerHandshakeSecret[i] != 0 {
			isNUllCount -= 1
			shsChecked = true
		}

		if !stsChecked && ServerTrafficSecret0[i] != 0 {
			isNUllCount -= 1
			stsChecked = true
		}

		if !esChecked && ExporterSecret[i] != 0 {
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
			m.logger.Error().Err(err).Msg("save packet error.")
		}
	case *event.SSLDataEvent:
		m.dumpSslData(eventStruct.(*event.SSLDataEvent))
	}
}

func (m *MOpenSSLProbe) dumpSslData(eventStruct *event.SSLDataEvent) {
	// BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR = 0x0400|0x0100 = 1280
	if eventStruct.Fd <= 0 && eventStruct.BioType > BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR {
		m.logger.Error().Uint32("pid", eventStruct.Pid).Uint32("fd", eventStruct.Fd).Str("address", eventStruct.Addr).Msg("SSLDataEvent's fd is 0")
		//return
	}
	addr := m.GetConn(eventStruct.Pid, eventStruct.Fd)
	m.logger.Debug().Uint32("pid", eventStruct.Pid).Uint32("bio_type", eventStruct.BioType).Uint32("fd", eventStruct.Fd).Str("address", addr).Msg("SSLDataEvent")
	if addr == ConnNotFound {
		eventStruct.Addr = DefaultAddr
	} else {
		eventStruct.Addr = addr
	}
	// m.processor.PcapFile(eventStruct)
	//if m.conf.GetHex() {
	//	m.logger.Println(eventStruct.StringHex())
	//} else {
	//	m.logger.Println(eventStruct.String())
	//}
	m.processor.Write(eventStruct)
}

func init() {
	RegisteFunc(NewOpenSSLProbe)
}

func NewOpenSSLProbe() IModule {
	mod := &MOpenSSLProbe{}
	mod.name = ModuleNameOpenssl
	mod.mType = ProbeTypeUprobe
	return mod
}
