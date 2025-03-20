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
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
)

const (
	ConnNotFound = "[TUPLE_NOT_FOUND]"
	DefaultTuple = "0.0.0.0:0-0.0.0.0:0"
	// OpenSSL the classes of BIOs
	// https://github.com/openssl/openssl/blob/openssl-3.0.0/include/openssl/bio.h.in
	BioTypeDescriptor = 0x0100
	BioTypeSourceSink = 0x0400
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

type ConnInfo struct {
	tuple string
	sock  uint64
}

type MOpenSSLProbe struct {
	MTCProbe
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	// pid[fd:(tuple,sock)]
	pidConns map[uint32]map[uint32]ConnInfo
	// sock:[pid,fd], for destroying conn
	sock2pidFd map[uint64][2]uint32
	pidLocker  sync.Locker

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
	m.pidConns = make(map[uint32]map[uint32]ConnInfo)
	m.sock2pidFd = make(map[uint64][2]uint32)
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

	err, verString := m.detectOpenssl(soPath)

	if err != nil && !errors.Is(err, ErrProbeOpensslVerNotFound) {
		m.logger.Error().Str("soPath", soPath).Err(err).Msg("OpenSSL/BoringSSL version check failed")
		return err
	}

	if errors.Is(err, ErrProbeOpensslVerNotFound) {
		// 未找到版本号， try libcrypto.so.x
		if strings.Contains(soPath, "libssl.so.3") {
			m.logger.Warn().Err(err).Str("soPath", soPath).Msg("OpenSSL/BoringSSL version not found.")
			m.logger.Warn().Msg("Try to detect libcrypto.so.3. If you have doubts, See https://github.com/gojue/ecapture/discussions/675 for more information.")

			// 从 libssl.so.3 中获取 libcrypto.so.3 的路径
			var libcryptoName = "libcrypto.so.3"
			var imd []string
			imd, err = getImpNeeded(soPath)
			if err == nil {
				for _, im := range imd {
					// 匹配 包含 libcrypto.so 字符的动态链接库库名
					if strings.Contains(im, "libcrypto.so") {
						libcryptoName = im
						break
					}
				}
			}
			soPath = strings.Replace(soPath, "libssl.so.3", libcryptoName, 1)
			m.logger.Info().Str("soPath", soPath).Str("imported", libcryptoName).Msg("Try to detect imported libcrypto.so ")
			err, verString = m.detectOpenssl(soPath)
			if err != nil && !errors.Is(err, ErrProbeOpensslVerNotFound) {
				m.logger.Warn().Err(err).Str("soPath", soPath).Str("imported", libcryptoName).Msgf("OpenSSL(libcrypto.so.3) version not found.%s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideLinux))
				return err
			}
			if errors.Is(err, ErrProbeOpensslVerNotFound) {
				m.logger.Info().Str("soPath", soPath).Str("imported", libcryptoName).Str("version", verString).Msg("OpenSSL/BoringSSL version found from imported libcrypto.so")
			}
		}
	}

	var bpfFileKey, bpfFile string
	isAndroid := m.conf.(*config.OpensslConfig).IsAndroid
	androidVer := m.conf.(*config.OpensslConfig).AndroidVer
	if verString != "" {
		m.conf.(*config.OpensslConfig).SslVersion = verString
		m.logger.Info().Str("origin versionKey", verString).Str("versionKeyLower", verString).Send()
		// find the sslVersion bpfFile from sslVersionBpfMap
		var found bool
		bpfFileKey = verString
		if isAndroid {
			// sometimes,boringssl version always was "boringssl 1.1.1" on android. but offsets are different.
			// see kern/boringssl_a_13_kern.c and kern/boringssl_a_14_kern.c
			// Perhaps we can utilize the Android Version to choose a specific version of boringssl.
			// use the corresponding bpfFile
			bpfFileKey = fmt.Sprintf("boringssl_a_%s", androidVer)
		}
		bpfFile, found = m.sslVersionBpfMap[bpfFileKey]
		if found {
			m.sslBpfFile = bpfFile
			m.logger.Info().Bool("Android", isAndroid).Str("library version", bpfFileKey).Msg("OpenSSL/BoringSSL version found")
			return nil
		} else {
			m.logger.Warn().Str("version", bpfFileKey).Err(ErrProbeOpensslVerBytecodeNotFound).Msg("Please send an issue to https://github.com/gojue/ecapture/issues")
		}
	}

	bpfFile = m.getSoDefaultBytecode(soPath, isAndroid)
	m.sslBpfFile = bpfFile
	if isAndroid {
		m.logger.Error().Msgf("OpenSSL/BoringSSL version not found, used default version.%s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideAndroid))
	} else {
		m.logger.Error().Msgf("OpenSSL/BoringSSL version not found, used default version.%s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideLinux))
	}
	m.logger.Error().Str("sslVersion", m.conf.(*config.OpensslConfig).SslVersion).Str("bpfFile", bpfFile).Send()
	return nil
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

func (m *MOpenSSLProbe) AddConn(pid, fd uint32, tuple string, sock uint64) {
	if fd <= 0 {
		m.logger.Info().Uint32("pid", pid).Uint32("fd", fd).Str("tuple", tuple).Msg("AddConn failed")
		return
	}
	// save
	m.pidLocker.Lock()
	defer m.pidLocker.Unlock()
	connMap, f := m.pidConns[pid]
	if !f {
		connMap = make(map[uint32]ConnInfo)
	}
	connMap[fd] = ConnInfo{tuple: tuple, sock: sock}
	m.pidConns[pid] = connMap

	m.sock2pidFd[sock] = [2]uint32{pid, fd}

	m.logger.Debug().Uint32("pid", pid).Uint32("fd", fd).Uint64("sock", sock).Str("tuple", tuple).Msg("AddConn success")
}

func (m *MOpenSSLProbe) DestroyConn(sock uint64) {
	m.pidLocker.Lock()
	defer m.pidLocker.Unlock()

	pidFd, ok := m.sock2pidFd[sock]
	if !ok {
		return
	}

	delete(m.sock2pidFd, sock)
	pid, fd := pidFd[0], pidFd[1]

	connMap, ok := m.pidConns[pid]
	if !ok {
		return
	}

	connInfo, ok := connMap[fd]
	if ok {
		//add sock consistency check to void tuple miss
		if connInfo.sock != sock {
			m.logger.Debug().Uint32("fd", fd).Uint64("sock", sock).Uint64("storedSock", connInfo.sock).Msg("DestroyConn skip")
			return
		}
		delete(connMap, fd)
		if len(connMap) == 0 {
			delete(m.pidConns, pid)
		}
	}

	m.logger.Debug().Uint32("pid", pid).Uint32("fd", fd).Uint64("sock", sock).Str("tuple", connInfo.tuple).Msg("DestroyConn success")
}

// DelConn process exit :fd is 0 , delete all pid map
func (m *MOpenSSLProbe) DelConn(sock uint64) {
	// deleteKeyAfterDelay 延迟3秒，删除指定键，
	// 延迟时间必需要大于event Processor的事件处理器合并事件的间隔。
	// 其次晚点删除，对业务影响上应该不大。
	time.AfterFunc(3*time.Second, func() {
		m.DestroyConn(sock)
	})
	return
}

func (m *MOpenSSLProbe) GetConn(pid, fd uint32) string {
	if fd <= 0 {
		return ConnNotFound
	}
	m.logger.Debug().Uint32("pid", pid).Uint32("fd", fd).Msg("GetConn")
	m.pidLocker.Lock()
	defer m.pidLocker.Unlock()
	connMap, f := m.pidConns[pid]
	if !f {
		return ConnNotFound
	}
	connInfo, f := connMap[fd]
	if !f {
		return ConnNotFound
	}
	return connInfo.tuple
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
	switch ev := eventStruct.(type) {
	case *event.ConnDataEvent:
		if ev.IsDestroy == 0 {
			m.AddConn(ev.Pid, ev.Fd, ev.Tuple, ev.Sock)
		} else {
			m.DelConn(ev.Sock)
		}
	case *event.MasterSecretEvent:
		m.saveMasterSecret(ev)
	case *event.MasterSecretBSSLEvent:
		m.saveMasterSecretBSSL(ev)
	case *event.TcSkbEvent:
		err := m.dumpTcSkb(ev)
		if err != nil {
			m.logger.Error().Err(err).Msg("save packet error.")
		}
	case *event.SSLDataEvent:
		m.dumpSslData(ev)
	}
}

func (m *MOpenSSLProbe) dumpSslData(eventStruct *event.SSLDataEvent) {
	// BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR = 0x0400|0x0100 = 1280
	if eventStruct.Fd <= 0 && eventStruct.BioType > BioTypeSourceSink|BioTypeDescriptor {
		m.logger.Error().Uint32("pid", eventStruct.Pid).Uint32("fd", eventStruct.Fd).Str("tuple", eventStruct.Tuple).Msg("SSLDataEvent's fd is 0")
		//return
	}
	tuple := m.GetConn(eventStruct.Pid, eventStruct.Fd)
	m.logger.Debug().Uint32("pid", eventStruct.Pid).Uint32("bio_type", eventStruct.BioType).Uint32("fd", eventStruct.Fd).Str("tuple", tuple).Msg("SSLDataEvent")
	if tuple == ConnNotFound {
		eventStruct.Tuple = DefaultTuple
	} else {
		eventStruct.Tuple = tuple
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
