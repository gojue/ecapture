package user

import (
	"bytes"
	"context"
	"ecapture/assets"
	"ecapture/pkg/event_processor"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
	"log"
	"math"
)

type MBashProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event_processor.IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MBashProbe) Init(ctx context.Context, logger *log.Logger, conf IConfig) error {
	this.Module.Init(ctx, logger)
	this.conf = conf
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event_processor.IEventStruct)
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
		return fmt.Errorf("couldn't find asset %v", err)
	}

	// setup the managers
	this.setupManagers()

	// initialize the bootstrap manager
	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v ", err)
	}

	// start the bootstrap manager
	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v ", err)
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
		return fmt.Errorf("couldn't stop manager %v ", err)
	}
	return this.Module.Close()
}

//  通过elf的常量替换方式传递数据
func (this *MBashProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(this.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(this.conf.GetUid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_errno",
			Value: uint32(this.Module.conf.(*BashConfig).ErrNo),
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

	this.logger.Printf("%s\tHOOK binrayPath:%s, FunctionName:readline\n", this.Name(), binaryPath)
	this.logger.Printf("%s\tHOOK binrayPath:%s, FunctionName:execute_command\n", this.Name(), binaryPath)

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uretprobe/bash_readline",
				EbpfFuncName:     "uretprobe_bash_readline",
				AttachToFuncName: "readline",
				//UprobeOffset: 0x8232, 	//若找不到 readline 函数，则使用offset便宜地址方式。
				BinaryPath: binaryPath, // 可能是 /bin/bash 也可能是 readline.so的真实地址
			},
			{
				Section:          "uretprobe/bash_retval",
				EbpfFuncName:     "uretprobe_bash_retval",
				AttachToFuncName: "execute_command",
				BinaryPath:       binaryPath, // 可能是 /bin/bash 也可能是 readline.so的真实地址
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
	}

	if this.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		this.bpfManagerOptions.ConstantEditors = this.constantEditor()
	}

}

func (this *MBashProbe) DecodeFun(em *ebpf.Map) (event_processor.IEventStruct, bool) {
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
	bashevent := &bashEvent{}
	bashevent.SetModule(this)
	this.eventFuncMaps[bashEventsMap] = bashevent

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
