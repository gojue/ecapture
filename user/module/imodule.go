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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gojue/ecapture/pkg/event_processor"
	ebpfenv "github.com/gojue/ecapture/pkg/util/ebpf"
	"github.com/gojue/ecapture/pkg/util/kernel"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/rs/zerolog"
)

type IModule interface {
	// Init 初始化
	Init(context.Context, *zerolog.Logger, config.IConfig, io.Writer) error

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

	Decode(*ebpf.Map, []byte) (event.IEventStruct, error)

	Events() []*ebpf.Map

	DecodeFun(p *ebpf.Map) (event.IEventStruct, bool)

	Dispatcher(event.IEventStruct)
}

const (
	KernelLess52Prefix = "_less52.o"
	BtfNotSupport      = "You can compile the BTF-free version by using the command `make nocore`, please read the Makefile for more information."
	BtfModeSwitch      = "If eCapture fails to run, try specifying the BTF mode. use `-b 2` to specify non-CORE mode."
)

type Module struct {
	isClosed       atomic.Bool
	opts           *ebpf.CollectionOptions
	reader         []IClose
	ctx            context.Context
	logger         *zerolog.Logger
	eventCollector io.Writer
	child          IModule
	// probe的名字
	name string

	// module的类型，uprobe,kprobe等
	mType string

	conf config.IConfig

	processor       *event_processor.EventProcessor
	isKernelLess5_2 bool // is  kernel version less 5.2
	isCoreUsed      bool // is core mode used
	errChan         chan error
}

// Init 对象初始化
func (m *Module) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, eventCollector io.Writer) error {
	m.isClosed.Store(false)
	m.ctx = ctx
	m.logger = logger
	m.errChan = make(chan error)
	m.isKernelLess5_2 = false //set false default
	m.eventCollector = eventCollector
	//var epl = epLogger{logger: logger}
	m.processor = event_processor.NewEventProcessor(eventCollector, conf.GetHex())
	kv, err := kernel.HostVersion()
	if err != nil {
		m.logger.Warn().Err(err).Msg("Unable to detect kernel version due to an error:%v.used non-Less5_2 bytecode.")
	} else {
		// it's safe to ignore err because we have checked it in main funcition
		if kv < kernel.VersionCode(5, 2, 0) {
			m.isKernelLess5_2 = true
			m.logger.Warn().Str("kernel", kv.String()).Msg("Kernel version is less than 5.2, Process filtering parameters do not take effect such as pid/uid.")
		}
	}

	logger.Info().Int("Pid", os.Getpid()).Str("Kernel Info", kv.String()).Send()

	if conf.GetBTF() == config.BTFModeAutoDetect {
		// 如果是自动检测模式
		m.autoDetectBTF()
	} else {
		// 如果是手动指定模式
		if conf.GetBTF() == config.BTFModeCore {
			m.isCoreUsed = true
		} else {
			m.isCoreUsed = false
		}
	}
	if m.isCoreUsed {
		m.logger.Info().Uint8("btfMode", conf.GetBTF()).Msg("BTF bytecode mode: CORE.")
	} else {
		m.logger.Info().Uint8("btfMode", conf.GetBTF()).Msg("BTF bytecode mode: non-CORE.")
	}
	return nil
}

func (m *Module) autoDetectBTF() {
	// 检测是否是容器
	isContainer, err := ebpfenv.IsContainer()
	if err == nil {
		if isContainer {
			m.logger.Warn().Msg("Your environment is like a container. We won't be able to detect the BTF configuration.\n" + BtfModeSwitch)
		}
		enable, e := ebpfenv.IsEnableBTF()
		if e != nil {
			m.logger.Warn().Err(e).Msg("Unable to find BTF configuration due to an error:%v.\n" + BtfNotSupport)
		}
		if enable {
			m.isCoreUsed = true
		}
	} else {
		m.logger.Warn().Err(err).Msg("Failed to detect container environment,This may cause eCapture not to work.\n" + BtfNotSupport)
	}
}
func (m *Module) geteBPFName(filename string) string {
	var newFilename = filename
	// CO-RE detect first
	if m.isCoreUsed {
		newFilename = strings.Replace(newFilename, ".o", "_core.o", 1)
	} else {
		newFilename = strings.Replace(newFilename, ".o", "_noncore.o", 1)
	}
	//
	if m.isKernelLess5_2 {
		newFilename = strings.Replace(newFilename, ".o", KernelLess52Prefix, 1)
	}

	return newFilename
}

func (m *Module) SetChild(module IModule) {
	m.child = module
}

func (m *Module) Start() error {
	panic("Module.Start() not implemented yet")
}

func (m *Module) Events() []*ebpf.Map {
	panic("Module.Events() not implemented yet")
}

func (m *Module) DecodeFun(p *ebpf.Map) (event.IEventStruct, bool) {
	panic("Module.DecodeFun() not implemented yet")
}

func (m *Module) Name() string {
	return m.name
}

func (m *Module) Run() error {
	m.logger.Info().Msg("Module.Run()")
	//  start
	err := m.child.Start()
	if err != nil {
		return err
	}

	go func() {
		m.run()
	}()

	go func() {
		err := m.processor.Serve()
		if err != nil {
			m.errChan <- fmt.Errorf("%s\tprocessor.Serve error:%v.", m.child.Name(), err)
			return
		}
	}()

	err = m.readEvents()
	if err != nil {
		return err
	}

	return nil
}
func (m *Module) Stop() error {
	return nil
}

// Stop shuts down Module
func (m *Module) run() {
	for {
		select {
		case _ = <-m.ctx.Done():
			// 由最上层Context的cancel函数关闭后调用 close().
			//err := m.child.Close()
			//if err != nil {
			//}
			m.logger.Info().Msg("Module closed,message recived from Context")
			return
		case err := <-m.errChan:
			m.logger.Warn().AnErr("Module closed,message recived from errChan", err).Send()
			return
		}
	}
}

func (m *Module) readEvents() error {
	var errChan = make(chan error, 8)
	go func() {
		for {
			select {
			case err := <-errChan:
				m.logger.Error().AnErr("readEvents error", err).Send()
			}
		}
	}()

	for _, e := range m.child.Events() {
		switch {
		case e.Type() == ebpf.RingBuf:
			m.ringbufEventReader(errChan, e)
		case e.Type() == ebpf.PerfEventArray:
			m.perfEventReader(errChan, e)
		default:
			return fmt.Errorf("%s\tunsupported mapType:%s , mapinfo:%s",
				m.child.Name(), e.Type().String(), e.String())
		}
	}

	return nil
}

func (m *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
	m.logger.Info().Int("mapSize(MB)", m.conf.GetPerCpuMapSize()/1024/1024).Msg("perfEventReader created")
	rd, err := perf.NewReader(em, m.conf.GetPerCpuMapSize())
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	m.reader = append(m.reader, rd)
	go func() {
		for {
			//判断ctx是不是结束
			select {
			case _ = <-m.ctx.Done():
				m.logger.Info().Msg("perfEventReader received close signal from context.Done().")
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				errChan <- fmt.Errorf("%s\treading from perf event reader: %s", m.child.Name(), err)
				return
			}

			if record.LostSamples != 0 {
				m.logger.Warn().Uint64("lostSamples", record.LostSamples).Msg("perf event ring buffer full, dropped samples")
				continue
			}

			var event event.IEventStruct
			event, err = m.child.Decode(em, record.RawSample)
			if err != nil {
				m.logger.Warn().Err(err).Msg("m.child.decode error")
				continue
			}

			// 上报数据
			m.Dispatcher(event)
		}
	}()
}

func (m *Module) ringbufEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := ringbuf.NewReader(em)
	if err != nil {
		errChan <- fmt.Errorf("%s\tcreating %s reader dns: %s", m.child.Name(), em.String(), err)
		return
	}
	m.reader = append(m.reader, rd)
	go func() {
		for {
			//判断ctx是不是结束
			select {
			case _ = <-m.ctx.Done():
				m.logger.Info().Msg("ringbufEventReader received close signal from context.Done().")
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					m.logger.Warn().Msg("ringbufEventReader received close signal from ringbuf reader.")
					return
				}
				errChan <- fmt.Errorf("%s\treading from ringbuf reader: %s", m.child.Name(), err)
				return
			}

			var e event.IEventStruct
			e, err = m.child.Decode(em, record.RawSample)
			if err != nil {
				m.logger.Warn().Err(err).Msg("m.child.decode error")
				continue
			}

			// 上报数据
			m.Dispatcher(e)
		}
	}()
}

func (m *Module) Decode(em *ebpf.Map, b []byte) (event event.IEventStruct, err error) {
	es, found := m.child.DecodeFun(em)
	if !found {
		err = fmt.Errorf("%s\tcan't found decode function :%s, address:%p", m.child.Name(), em.String(), em)
		return
	}

	te := es.Clone()
	err = te.Decode(b)
	if err != nil {
		return nil, err
	}
	return te, nil
}

// Dispatcher 写入数据，或者上传到远程数据库，写入到其他chan 等。
func (m *Module) Dispatcher(e event.IEventStruct) {
	// check is Module shutdown.
	if m.isClosed.Load() {
		m.logger.Error().Bool("isClosed", m.isClosed.Load()).Msg("eCapture iModule is closed, ignore event.")
		return
	}
	// If Hex mode is enabled, data in hex format is directly printed for event processor and output events
	if m.conf.GetHex() {
		if e.EventType() == event.EventTypeEventProcessor || e.EventType() == event.EventTypeOutput {
			s := e.StringHex()
			if s == "" {
				return
			}
			//m.logger.Info().Msg(s)
			_, _ = m.eventCollector.Write([]byte(s))
			return
		}
	}

	// If Hex mode is not enabled, or if the event_processor and output events are not enabled,
	// they will be handled according to multiple branches of the switch
	switch e.EventType() {
	case event.EventTypeOutput:
		s := e.String()
		if s == "" {
			return
		}
		//m.logger.Info().Msg(s)
		_, _ = m.eventCollector.Write([]byte(s))
	case event.EventTypeEventProcessor:
		m.processor.Write(e)
	case event.EventTypeModuleData:
		// Save to cache
		m.child.Dispatcher(e)
	default:
		m.logger.Warn().Uint8("eventType", uint8(e.EventType())).Msg("unknown event type")
	}
}

func (m *Module) Close() error {
	m.isClosed.Store(true)
	m.logger.Info().Msg("iModule module close")
	for _, iClose := range m.reader {
		if err := iClose.Close(); err != nil {
			return err
		}
	}
	err := m.processor.Close()
	return err
}
