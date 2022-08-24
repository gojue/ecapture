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
	manager "github.com/ehids/ebpfmanager"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
	"hash"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	CONN_NOT_FOUND = "[ADDR_NOT_FOUND]"

	// tls 1.2
	CLIENT_RANDOM = "CLIENT_RANDOM"

	// tls 1.3
	SERVER_HANDSHAKE_TRAFFIC_SECRET = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	EXPORTER_SECRET                 = "EXPORTER_SECRET"
	SERVER_TRAFFIC_SECRET_0         = "SERVER_TRAFFIC_SECRET_0"
	CLIENT_HANDSHAKE_TRAFFIC_SECRET = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	CLIENT_TRAFFIC_SECRET_0         = "CLIENT_TRAFFIC_SECRET_0"
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
	EBPFPROGRAMTYPE_OPENSSL_TC EBPFPROGRAMTYPE = iota
	EBPFPROGRAMTYPE_OPENSSL_UPROBE
)

type MOpenSSLProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	// pid[fd:Addr]
	pidConns map[uint32]map[uint32]string

	keyloggerFilename string
	keylogger         *os.File
	masterKeys        map[string]bool
	eBPFProgramType   EBPFPROGRAMTYPE
	pcapngFilename    string
	ifIdex            int
	ifName            string
	pcapWriter        *pcapgo.NgWriter
	startTime         uint64
	bootTime          uint64
	tcPackets         []*TcPacket
	masterKeyBuffer   *bytes.Buffer
	tcPacketLocker    *sync.Mutex
}

//对象初始化
func (this *MOpenSSLProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	this.pidConns = make(map[uint32]map[uint32]string)
	this.masterKeys = make(map[string]bool)
	//fd := os.Getpid()
	this.keyloggerFilename = "ecapture_masterkey.log"
	file, err := os.OpenFile(this.keyloggerFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	this.keylogger = file
	var writeFile = this.conf.(*config.OpensslConfig).Write
	if len(writeFile) > 0 {
		this.eBPFProgramType = EBPFPROGRAMTYPE_OPENSSL_TC
		fileInfo, err := filepath.Abs(writeFile)
		if err != nil {
			return err
		}
		this.pcapngFilename = fileInfo
	} else {
		this.eBPFProgramType = EBPFPROGRAMTYPE_OPENSSL_UPROBE
		this.logger.Printf("%s\tmaster key keylogger: %s\n", this.Name(), this.keyloggerFilename)
	}

	var ts unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return err
	}
	startTime := ts.Nano()
	// Calculate the boot time using the monotonic time (since this is the clock we're using as a timestamp)
	// Note: this is NOT the real boot time, as the monotonic clock doesn't take into account system sleeps.
	bootTime := time.Now().UnixNano() - startTime

	this.startTime = uint64(startTime)
	this.bootTime = uint64(bootTime)

	this.tcPackets = make([]*TcPacket, 0, 1024)
	this.tcPacketLocker = &sync.Mutex{}
	this.masterKeyBuffer = bytes.NewBuffer([]byte{})
	return nil
}

func (this *MOpenSSLProbe) Start() error {
	return this.start()
}

func (this *MOpenSSLProbe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/openssl_kern.o")
	if err != nil {
		return fmt.Errorf("%s\tcouldn't find asset %v .", this.Name(), err)
	}

	// setup the managers
	switch this.eBPFProgramType {
	case EBPFPROGRAMTYPE_OPENSSL_TC:
		this.logger.Printf("%s\tTC MODEL\n", this.Name())
		err = this.setupManagersTC()
	case EBPFPROGRAMTYPE_OPENSSL_UPROBE:
		this.logger.Printf("%s\tUPROBE MODEL\n", this.Name())
		err = this.setupManagersUprobe()
	default:
		this.logger.Printf("%s\tUPROBE MODEL\n", this.Name())
		err = this.setupManagersUprobe()
	}

	if err != nil {
		return fmt.Errorf("tls module couldn't find binPath %v .", err)
	}

	// initialize the bootstrap manager
	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}

	// 加载map信息，map对应events decode表。
	switch this.eBPFProgramType {
	case EBPFPROGRAMTYPE_OPENSSL_TC:
		err = this.initDecodeFunTC()
	case EBPFPROGRAMTYPE_OPENSSL_UPROBE:
		err = this.initDecodeFun()
	default:
		err = this.initDecodeFun()
	}
	if err != nil {
		return err
	}

	return nil
}

func (this *MOpenSSLProbe) Close() error {
	if this.eBPFProgramType == EBPFPROGRAMTYPE_OPENSSL_TC {
		this.logger.Printf("%s\tsaving pcapng file %s\n", this.Name(), this.pcapngFilename)
		err := this.savePcapng()
		if err != nil {
			return err
		}
	}

	this.logger.Printf("%s\tclose. \n", this.Name())

	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	return this.Module.Close()
}

//  通过elf的常量替换方式传递数据
func (this *MOpenSSLProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(this.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(this.conf.GetUid()),
		},
		{
			Name:  "target_port",
			Value: uint32(this.conf.(*config.OpensslConfig).Port),
		},
	}

	if this.conf.GetPid() <= 0 {
		this.logger.Printf("%s\ttarget all process. \n", this.Name())
	} else {
		this.logger.Printf("%s\ttarget PID:%d \n", this.Name(), this.conf.GetPid())
	}

	if this.conf.GetUid() <= 0 {
		this.logger.Printf("%s\ttarget all users. \n", this.Name())
	} else {
		this.logger.Printf("%s\ttarget UID:%d \n", this.Name(), this.conf.GetUid())
	}

	return editor
}

func (this *MOpenSSLProbe) setupManagersUprobe() error {
	var binaryPath, libPthread string
	switch this.conf.(*config.OpensslConfig).ElfType {
	case config.ELF_TYPE_BIN:
		binaryPath = this.conf.(*config.OpensslConfig).Curlpath
	case config.ELF_TYPE_SO:
		binaryPath = this.conf.(*config.OpensslConfig).Openssl
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libssl.so.1.1"
	}

	libPthread = this.conf.(*config.OpensslConfig).Pthread
	if libPthread == "" {
		libPthread = "/lib/x86_64-linux-gnu/libpthread.so.0"
	}
	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	this.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", this.Name(), this.conf.(*config.OpensslConfig).ElfType, binaryPath)
	this.logger.Printf("%s\tlibPthread so Path:%s\n", this.Name(), libPthread)

	this.bpfManager = &manager.Manager{
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
			// for SSL_write_ex \ SSL_read_ex
			/*
				{
					Section:          "uprobe/SSL_write",
					EbpfFuncName:     "probe_entry_SSL_write",
					AttachToFuncName: "SSL_write_ex",
					BinaryPath:       binaryPath,
					UID:              "uprobe_SSL_write_ex",
				},
				{
					Section:          "uretprobe/SSL_write",
					EbpfFuncName:     "probe_ret_SSL_write",
					AttachToFuncName: "SSL_write_ex",
					BinaryPath:       binaryPath,
					UID:              "uretprobe_SSL_write_ex",
				},
				{
					Section:          "uprobe/SSL_read",
					EbpfFuncName:     "probe_entry_SSL_read",
					AttachToFuncName: "SSL_read_ex",
					BinaryPath:       binaryPath,
					UID:              "uprobe_SSL_read_ex",
				},
				{
					Section:          "uretprobe/SSL_read",
					EbpfFuncName:     "probe_ret_SSL_read",
					AttachToFuncName: "SSL_read_ex",
					BinaryPath:       binaryPath,
					UID:              "uretprobe_SSL_read_ex",
				},
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
				AttachToFuncName: "SSL_write",
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

	this.bpfManagerOptions = manager.Options{
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

	if this.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		this.bpfManagerOptions.ConstantEditors = this.constantEditor()
	}
	return nil
}

func (this *MOpenSSLProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MOpenSSLProbe) initDecodeFun() error {
	//SSLDumpEventsMap 与解码函数映射
	SSLDumpEventsMap, found, err := this.bpfManager.GetMap("tls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tls_events")
	}
	this.eventMaps = append(this.eventMaps, SSLDumpEventsMap)
	sslEvent := &event.SSLDataEvent{}
	//sslEvent.SetModule(this)
	this.eventFuncMaps[SSLDumpEventsMap] = sslEvent

	ConnEventsMap, found, err := this.bpfManager.GetMap("connect_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:connect_events")
	}
	this.eventMaps = append(this.eventMaps, ConnEventsMap)
	connEvent := &event.ConnDataEvent{}
	//connEvent.SetModule(this)
	this.eventFuncMaps[ConnEventsMap] = connEvent

	MasterkeyEventsMap, found, err := this.bpfManager.GetMap("mastersecret_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	this.eventMaps = append(this.eventMaps, MasterkeyEventsMap)
	masterkeyEvent := &event.MasterSecretEvent{}
	//masterkeyEvent.SetModule(this)
	this.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}

func (this *MOpenSSLProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func (this *MOpenSSLProbe) AddConn(pid, fd uint32, addr string) {
	// save to map
	var m map[uint32]string
	var f bool
	m, f = this.pidConns[pid]
	if !f {
		m = make(map[uint32]string)
	}
	m[fd] = addr
	this.pidConns[pid] = m
	return
}

// process exit :fd is 0 , delete all pid map
// fd exit :pid > 0, fd > 0, delete fd value
// TODO add fd * pid exit event hook
func (this *MOpenSSLProbe) DelConn(pid, fd uint32) {
	// delete from map
	if pid == 0 {
		return
	}

	if fd == 0 {
		delete(this.pidConns, pid)
	}

	var m map[uint32]string
	var f bool
	m, f = this.pidConns[pid]
	if !f {
		return
	}
	delete(m, fd)
	this.pidConns[pid] = m
	return
}

func (this *MOpenSSLProbe) GetConn(pid, fd uint32) string {
	addr := ""
	var m map[uint32]string
	var f bool
	m, f = this.pidConns[pid]
	if !f {
		return CONN_NOT_FOUND
	}

	addr, f = m[fd]
	if !f {
		return CONN_NOT_FOUND
	}
	return addr
}

func (this *MOpenSSLProbe) saveMasterSecret(secretEvent *event.MasterSecretEvent) {

	var k = fmt.Sprintf("%02x", secretEvent.ClientRandom)

	_, f := this.masterKeys[k]
	if f {
		// 已存在该随机数的masterSecret，不需要重复写入
		return
	}
	this.masterKeys[k] = true

	// save to file
	var b *bytes.Buffer
	switch secretEvent.Version {
	case event.TLS1_2_VERSION:
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", CLIENT_RANDOM, secretEvent.ClientRandom, secretEvent.MasterKey))
	case event.TLS1_3_VERSION:
		// secretEvent.CipherId = 0x1301    // 50336513

		var transcript hash.Hash
		// check crypto type
		switch uint16(secretEvent.CipherId & 0x0000FFFF) {
		case hkdf.TLS_AES_128_GCM_SHA256:
			transcript = crypto.SHA256.New()
		case hkdf.TLS_AES_256_GCM_SHA384:
			transcript = crypto.SHA384.New()
		case hkdf.TLS_CHACHA20_POLY1305_SHA256:
			transcript = crypto.SHA256.New()
		default:
			this.logger.Printf("non-tls 1.3 ciphersuite in tls13_hkdf_expand, CipherId: %d", secretEvent.CipherId)
			return
		}
		transcript.Write(secretEvent.HandshakeTrafficHash[:])
		clientSecret := hkdf.DeriveSecret(secretEvent.HandshakeSecret[:], hkdf.ClientHandshakeTrafficLabel, transcript)
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientHandshake, secretEvent.ClientRandom, clientSecret))

		serverHandshakeSecret := hkdf.DeriveSecret(secretEvent.HandshakeSecret[:], hkdf.ServerHandshakeTrafficLabel, transcript)
		b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientHandshake, secretEvent.ClientRandom, serverHandshakeSecret))

		transcript.Reset()
		transcript.Write(secretEvent.ServerFinishedHash[:])

		trafficSecret := hkdf.DeriveSecret(secretEvent.MasterSecret[:], hkdf.ClientApplicationTrafficLabel, transcript)
		b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelClientTraffic, secretEvent.ClientRandom, trafficSecret))
		serverSecret := hkdf.DeriveSecret(secretEvent.MasterSecret[:], hkdf.ServerApplicationTrafficLabel, transcript)
		b.WriteString(fmt.Sprintf("%s %02x %02x\n", hkdf.KeyLogLabelServerTraffic, secretEvent.ClientRandom, serverSecret))

		// TODO MasterSecret sum
	default:
		b = bytes.NewBufferString(fmt.Sprintf("%s %02x %02x\n", CLIENT_RANDOM, secretEvent.ClientRandom, secretEvent.MasterKey))
	}
	v := event.TlsVersion{Version: secretEvent.Version}
	l, e := this.keylogger.WriteString(b.String())
	if e != nil {
		this.logger.Fatalf("%s: save CLIENT_RANDOM to file error:%s", v.String(), e.Error())
		return
	}

	//
	switch this.eBPFProgramType {
	case EBPFPROGRAMTYPE_OPENSSL_TC:
		this.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", v.String(), secretEvent.ClientRandom, l)
		e = this.savePcapngSslKeyLog(b.Bytes())
		if e != nil {
			this.logger.Fatalf("%s: save CLIENT_RANDOM to pcapng error:%s", v.String(), e.Error())
			return
		}
	default:
		this.logger.Printf("%s: save CLIENT_RANDOM %02x to file success, %d bytes", v.String(), secretEvent.ClientRandom, l)
	}
}

func (this *MOpenSSLProbe) Dispatcher(eventStruct event.IEventStruct) {
	// detect eventStruct type
	switch eventStruct.(type) {
	case *event.ConnDataEvent:
		this.AddConn(eventStruct.(*event.ConnDataEvent).Pid, eventStruct.(*event.ConnDataEvent).Fd, eventStruct.(*event.ConnDataEvent).Addr)
	case *event.MasterSecretEvent:
		this.saveMasterSecret(eventStruct.(*event.MasterSecretEvent))
	case *event.TcSkbEvent:
		this.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
	}
	//this.logger.Println(eventStruct)
}

func init() {
	mod := &MOpenSSLProbe{}
	mod.name = MODULE_NAME_OPENSSL
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
