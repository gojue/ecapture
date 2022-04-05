package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"os"
)

type IModule interface {
	// Init 初始化
	Init(context.Context, *log.Logger, IConfig) error

	// Name 获取当前module的名字
	Name() string

	// Run 事件监听感知
	Run() error

	// Start 启动模块
	Start() error

	// Stop 停止模块
	Stop() error

	// Close 关闭退出
	Close() error

	SetChild(module IModule)

	Decode(*ebpf.Map, []byte) (string, error)

	Events() []*ebpf.Map

	DecodeFun(p *ebpf.Map) (IEventStruct, bool)

	Write(string)
}

type Module struct {
	opts   *ebpf.CollectionOptions
	reader []IClose
	ctx    context.Context
	logger *log.Logger
	child  IModule
	// probe的名字
	name string

	// module的类型，uprobe,kprobe等
	mType string

	conf IConfig
}

// Init 对象初始化
func (this *Module) Init(ctx context.Context, logger *log.Logger) {
	this.ctx = ctx
	this.logger = logger
	return
}

func (this *Module) SetChild(module IModule) {
	this.child = module
}

func (this *Module) Start() error {
	panic("Module.Start() not implemented yet")
}

func (this *Module) Events() []*ebpf.Map {
	panic("Module.Events() not implemented yet")
}

func (this *Module) DecodeFun(p *ebpf.Map) (IEventStruct, bool) {
	panic("Module.DecodeFun() not implemented yet")
}

func (this *Module) Name() string {
	return this.name
}

func (this *Module) Run() error {
	//  start
	err := this.child.Start()
	if err != nil {
		return err
	}

	err = this.readEvents()
	if err != nil {
		return err
	}

	go func() {
		this.run()
	}()
	return nil
}
func (this *Module) Stop() error {
	return nil
}

// Stop shuts down Module
func (this *Module) run() {
	for {
		select {
		case _ = <-this.ctx.Done():
			err := this.child.Stop()
			if err != nil {
				this.logger.Fatalf("stop Module:%s error:%v.", this.child.Name(), err)
			}
			return
		}
	}
}

func (this *Module) readEvents() error {
	var errChan = make(chan error, 8)
	for _, event := range this.child.Events() {
		switch {
		case event.Type() == ebpf.RingBuf:
			go this.ringbufEventReader(errChan, event)
		case event.Type() == ebpf.PerfEventArray:
			go this.perfEventReader(errChan, event)
		default:
			errChan <- fmt.Errorf("Not support mapType:%s , mapinfo:%s", event.Type().String(), event.String())
		}
	}

	for {
		select {
		case err := <-errChan:
			return err
		}
	}
}

func (this *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := perf.NewReader(em, os.Getpagesize()*64)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	defer rd.Close()
	for {
		//判断ctx是不是结束
		select {
		case _ = <-this.ctx.Done():
			log.Printf("readEvent recived close signal from context.Done.")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			errChan <- fmt.Errorf("reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		var result string
		result, err = this.child.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("this.child.decode error:%v", err)
			continue
		}

		// 上报数据
		this.Write(result)
	}
}

func (this *Module) ringbufEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := ringbuf.NewReader(em)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	defer rd.Close()
	for {
		//判断ctx是不是结束
		select {
		case _ = <-this.ctx.Done():
			this.logger.Printf("readEvent recived close signal from context.Done.")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				this.logger.Println("Received signal, exiting..")
				return
			}
			errChan <- fmt.Errorf("reading from ringbuf reader: %s", err)
			return
		}

		var result string
		result, err = this.child.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("this.child.decode error:%v", err)
			continue
		}

		// 上报数据
		this.Write(result)
	}
}

func (this *Module) EventsDecode(payload []byte, es IEventStruct) (s string, err error) {
	te := es.Clone()
	err = te.Decode(payload)
	if err != nil {
		return
	}
	if this.conf.GetHex() {
		s = te.StringHex()
	} else {
		s = te.String()
	}
	return
}

func (this *Module) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	es, found := this.child.DecodeFun(em)
	if !found {
		err = fmt.Errorf("can't found decode function :%s, address:%p", em.String(), em)
		return
	}
	result, err = this.EventsDecode(b, es)
	if err != nil {
		return
	}
	return
}

// 写入数据，或者上传到远程数据库，写入到其他chan 等。
func (this *Module) Write(result string) {
	this.child.Write(result)
}
