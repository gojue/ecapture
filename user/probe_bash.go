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

type MBashProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MBashProbe) Init(ctx context.Context, logger *log.Logger, conf IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MBashProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MBashProbe) start() error {

	// fetch ebpf assets
	byteBuf, err := assets.Asset("user/bytecode/bash_kern.o")
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

func (this *MBashProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

//  通过elf的常量替换方式传递数据
func (e *MBashProbe) constantEditor() []manager.ConstantEditor {
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

func (this *MBashProbe) setupManagers() {
	var binaryPath string
	switch this.conf.(*BashConfig).elfType {
	case ELF_TYPE_BIN:
		binaryPath = this.conf.(*BashConfig).Bashpath
	case ELF_TYPE_SO:
		binaryPath = this.conf.(*BashConfig).Readline
	default:
		binaryPath = "/bin/bash"
	}

	this.logger.Printf("HOOK binrayPath:%s, FunctionName:readline\n", binaryPath)

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uretprobe/bash_readline",
				EbpfFuncName:     "uretprobe_bash_readline",
				AttachToFuncName: "readline",
				//UprobeOffset: 0x8232, 	//若找不到 readline 函数，则使用offset便宜地址方式。
				BinaryPath: binaryPath, // 可能是 /bin/bash 也可能是 readline.so的真实地址
			},
		},

		Maps: []*manager.Map{
			{
				Name: "events",
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

func (this *MBashProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MBashProbe) initDecodeFun() error {
	//bashEventsMap 与解码函数映射
	bashEventsMap, found, err := this.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, bashEventsMap)
	this.eventFuncMaps[bashEventsMap] = &bashEvent{}

	return nil
}

func (this *MBashProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MBashProbe{}
	mod.name = MODULE_NAME_BASH
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
