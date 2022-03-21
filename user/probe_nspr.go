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

type MNsprProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MNsprProbe) Init(ctx context.Context, logger *log.Logger, conf IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MNsprProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MNsprProbe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/nspr_kern.o")
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

func (this *MNsprProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

//  通过elf的常量替换方式传递数据
func (e *MNsprProbe) constantEditor() []manager.ConstantEditor {
	//TODO
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(e.conf.GetPid()),
			//FailOnMissing: true,
		},
	}

	if e.conf.GetPid() <= 0 {
		e.logger.Printf("target all process. \n")
	} else {
		e.logger.Printf("target PID:%d \n", e.conf.GetPid())
	}
	return editor
}

func (this *MNsprProbe) setupManagers() {
	var binaryPath string
	switch this.conf.(*NsprConfig).elfType {
	case ELF_TYPE_BIN:
		binaryPath = this.conf.(*NsprConfig).Firefoxpath
	case ELF_TYPE_SO:
		binaryPath = this.conf.(*NsprConfig).Nsprpath
	default:
		//如果没找到
		binaryPath = "/lib/x86_64-linux-gnu/libnspr4.so"
	}

	this.logger.Printf("HOOK type:%d, binrayPath:%s\n", this.conf.(*NsprConfig).elfType, binaryPath)

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/PR_Write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "PR_Write",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/PR_Write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "PR_Write",
				BinaryPath:       binaryPath,
			},

			// for PR_Send start
			{
				UID:              "PR_Write-PR_Send",
				Section:          "uprobe/PR_Write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "PR_Send",
				BinaryPath:       binaryPath,
			},
			{
				UID:              "PR_Write-PR_Send",
				Section:          "uretprobe/PR_Write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "PR_Send",
				BinaryPath:       binaryPath,
			},
			// for PR_Send end

			{
				Section:          "uprobe/PR_Read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "PR_Read",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/PR_Read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "PR_Read",
				BinaryPath:       binaryPath,
			},

			{
				UID:              "PR_Read-PR_Recv",
				Section:          "uprobe/PR_Read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "PR_Recv",
				BinaryPath:       binaryPath,
			},
			{
				UID:              "PR_Read-PR_Recv",
				Section:          "uretprobe/PR_Read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "PR_Recv",
				BinaryPath:       binaryPath,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "nspr_events",
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
		// 填充 RewriteContants 对应map
		ConstantEditors: this.constantEditor(),
	}
}

func (this *MNsprProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MNsprProbe) initDecodeFun() error {
	// NsprEventsMap 与解码函数映射
	NsprEventsMap, found, err := this.bpfManager.GetMap("nspr_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:nspr_events")
	}
	this.eventMaps = append(this.eventMaps, NsprEventsMap)
	this.eventFuncMaps[NsprEventsMap] = &NsprDataEvent{}

	return nil
}

func (this *MNsprProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MNsprProbe{}
	mod.name = MODULE_NAME_NSPR
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
