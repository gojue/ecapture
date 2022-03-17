package user

import (
	"bytes"
	"context"
	"ecapture/assets"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"log"
	"math"
)

type MSSLDumpProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MSSLDumpProbe) Init(ctx context.Context, logger *log.Logger) error {
	this.Module.Init(ctx, logger)
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MSSLDumpProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MSSLDumpProbe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/ssldump_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	this.setupManagers()

	// initialize the bootstrap manager
	if err := this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := this.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MSSLDumpProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (this *MSSLDumpProbe) setupManagers() {
	var bash, binaryPath string
	bash = "/usr/bin/curl"
	soPath, e := getDynPathByElf(bash, "libssl.so")
	if e != nil {
		this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		binaryPath = bash
	} else {
		binaryPath = soPath
	}

	//如果没找到
	if binaryPath == "" {
		binaryPath = "/lib/x86_64-linux-gnu/libssl.so.1.1"
	}

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/SSL_write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "SSL_write",
				//UprobeOffset:     0x386B0,
				BinaryPath: binaryPath,
			},
			{
				Section:          "uretprobe/SSL_write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "SSL_write",
				//UprobeOffset:     0x386B0,
				BinaryPath: binaryPath,
			},
			{
				Section:          "uprobe/SSL_read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "SSL_read",
				//UprobeOffset:     0x38380,
				BinaryPath: binaryPath,
			},
			{
				Section:          "uretprobe/SSL_read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "SSL_read",
				//UprobeOffset:     0x38380,
				BinaryPath: binaryPath,
			},
			/**/
		},

		Maps: []*manager.Map{
			{
				Name: "tls_events",
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
}

func (this *MSSLDumpProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MSSLDumpProbe) initDecodeFun() error {
	//SSLDumpEventsMap 与解码函数映射
	SSLDumpEventsMap, found, err := this.bpfManager.GetMap("tls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tls_events")
	}
	this.eventMaps = append(this.eventMaps, SSLDumpEventsMap)
	this.eventFuncMaps[SSLDumpEventsMap] = &SSLDataEvent{}

	return nil
}

func (this *MSSLDumpProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MSSLDumpProbe{}
	mod.name = "EBPFProbeSSLDump"
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
