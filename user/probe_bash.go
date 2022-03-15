package user

import (
	"bytes"
	"context"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"log"
	"math"
	"ssldump/assets"
)

type MBashProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MBashProbe) Init(ctx context.Context, logger *log.Logger) error {
	this.Module.Init(ctx, logger)
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

func (this *MBashProbe) setupManagers() {
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uretprobe/bash_readline",
				EbpfFuncName:     "uretprobe_bash_readline",
				AttachToFuncName: "readline",
				BinaryPath:       "/bin/bash",
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
	mod.name = "EBPFProbeBash"
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
