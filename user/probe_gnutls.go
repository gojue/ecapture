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
	"os"
)

type MGnutlsProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MGnutlsProbe) Init(ctx context.Context, logger *log.Logger, conf IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MGnutlsProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MGnutlsProbe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/gnutls_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	err = this.setupManagers()
	if err != nil {
		return errors.Wrap(err, "tls(gnutls) module couldn't find binPath.")
	}

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

func (this *MGnutlsProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

//  通过elf的常量替换方式传递数据
func (this *MGnutlsProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(this.conf.GetPid()),
			//FailOnMissing: true,
		},
	}

	if this.conf.GetPid() <= 0 {
		this.logger.Printf("target all process. \n")
	} else {
		this.logger.Printf("target PID:%d \n", this.conf.GetPid())
	}
	return editor
}

func (this *MGnutlsProbe) setupManagers() error {
	var binaryPath string
	switch this.conf.(*GnutlsConfig).elfType {
	case ELF_TYPE_BIN:
		binaryPath = this.conf.(*GnutlsConfig).Curlpath
	case ELF_TYPE_SO:
		binaryPath = this.conf.(*GnutlsConfig).Gnutls
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libgnutls.so.30"
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	this.logger.Printf("HOOK type:%d, binrayPath:%s\n", this.conf.(*GnutlsConfig).elfType, binaryPath)

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/gnutls_record_send",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "gnutls_record_send",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/gnutls_record_send",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "gnutls_record_send",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uprobe/gnutls_record_recv",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "gnutls_record_recv",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/gnutls_record_recv",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "gnutls_record_recv",
				BinaryPath:       binaryPath,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "gnutls_events",
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

func (this *MGnutlsProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MGnutlsProbe) initDecodeFun() error {
	//GnutlsEventsMap 与解码函数映射
	GnutlsEventsMap, found, err := this.bpfManager.GetMap("gnutls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:gnutls_events")
	}
	this.eventMaps = append(this.eventMaps, GnutlsEventsMap)
	this.eventFuncMaps[GnutlsEventsMap] = &GnutlsDataEvent{}

	return nil
}

func (this *MGnutlsProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MGnutlsProbe{}
	mod.name = MODULE_NAME_GNUTLS
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
