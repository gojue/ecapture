package user

import (
	"bytes"
	"context"
	"ecapture/assets"
	"ecapture/pkg/event_processor"
	"fmt"
	"log"
	"math"
	"os"

	"errors"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

const CONN_NOT_FOUND = "[ADDR_NOT_FOUND]"

type MOpenSSLProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event_processor.IEventStruct
	eventMaps         []*ebpf.Map

	// pid[fd:Addr]
	pidConns map[uint32]map[uint32]string
}

//对象初始化
func (this *MOpenSSLProbe) Init(ctx context.Context, logger *log.Logger, conf IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event_processor.IEventStruct)
	this.pidConns = make(map[uint32]map[uint32]string)
	return nil
}

func (this *MOpenSSLProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MOpenSSLProbe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/openssl_kern.o")
	if err != nil {
		return fmt.Errorf("couldn't find asset %v .", err)
	}

	// setup the managers
	err = this.setupManagers()
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
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MOpenSSLProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	return nil
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

func (this *MOpenSSLProbe) setupManagers() error {
	var binaryPath, libPthread string
	switch this.conf.(*OpensslConfig).elfType {
	case ELF_TYPE_BIN:
		binaryPath = this.conf.(*OpensslConfig).Curlpath
	case ELF_TYPE_SO:
		binaryPath = this.conf.(*OpensslConfig).Openssl
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libssl.so.1.1"
	}

	libPthread = this.conf.(*OpensslConfig).Pthread
	if libPthread == "" {
		libPthread = "/lib/x86_64-linux-gnu/libpthread.so.0"
	}
	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	this.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", this.Name(), this.conf.(*OpensslConfig).elfType, binaryPath)
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
				Name: "masterkey_events",
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

func (this *MOpenSSLProbe) DecodeFun(em *ebpf.Map) (event_processor.IEventStruct, bool) {
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
	sslEvent := &SSLDataEvent{}
	sslEvent.SetModule(this)
	this.eventFuncMaps[SSLDumpEventsMap] = sslEvent

	ConnEventsMap, found, err := this.bpfManager.GetMap("connect_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:connect_events")
	}
	this.eventMaps = append(this.eventMaps, ConnEventsMap)
	connEvent := &ConnDataEvent{}
	connEvent.SetModule(this)
	this.eventFuncMaps[ConnEventsMap] = connEvent

	MasterkeyEventsMap, found, err := this.bpfManager.GetMap("masterkey_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:masterkey_events")
	}
	this.eventMaps = append(this.eventMaps, MasterkeyEventsMap)
	masterkeyEvent := &MasterKeyEvent{}
	masterkeyEvent.SetModule(this)
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

func (this *MOpenSSLProbe) Dispatcher(event event_processor.IEventStruct) {
	// detect event type TODO
	this.AddConn(event.(*ConnDataEvent).Pid, event.(*ConnDataEvent).Fd, event.(*ConnDataEvent).Addr)
	//this.logger.Println(event)
}

func init() {
	mod := &MOpenSSLProbe{}
	mod.name = MODULE_NAME_OPENSSL
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
