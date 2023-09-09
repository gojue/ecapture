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
	"ecapture/pkg/event_processor"
	"ecapture/pkg/util/kernel"
	"ecapture/user/config"
	"ecapture/user/event"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"os"
	"strings"
)

type IModule interface {
	// Init 初始化
	Init(context.Context, *log.Logger, config.IConfig) error

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

const KernelLess52Prefix = "_less52.o"

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

	conf config.IConfig

	processor       *event_processor.EventProcessor
	isKernelLess5_2 bool //is  kernel version less 5.2
}

// Init 对象初始化
func (m *Module) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) {
	m.ctx = ctx
	m.logger = logger
	m.processor = event_processor.NewEventProcessor(logger, conf.GetHex())
	m.isKernelLess5_2 = false //set false default
	kv, err := kernel.HostVersion()
	if err != nil {
		// nothing to do.
	}
	if kv < kernel.VersionCode(5, 2, 0) {
		m.isKernelLess5_2 = true
	}
}

func (m *Module) geteBPFName(filename string) string {
	if m.isKernelLess5_2 {
		return strings.Replace(filename, ".o", KernelLess52Prefix, 1)
	}
	return filename
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
	m.logger.Printf("ECAPTURE ::\tModule.Run()")
	//  start
	err := m.child.Start()
	if err != nil {
		return err
	}

	go func() {
		m.run()
	}()

	go func() {
		m.processor.Serve()
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
			err := m.child.Stop()
			if err != nil {
				m.logger.Fatalf("%s\t stop Module error:%v.", m.child.Name(), err)
			}
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
				m.logger.Printf("%s\treadEvents error:%v", m.child.Name(), err)
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
	rd, err := perf.NewReader(em, os.Getpagesize()*BufferSizeOfEbpfMap)
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
				m.logger.Printf("%s\tperfEventReader received close signal from context.Done().", m.child.Name())
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
				m.logger.Printf("%s\tperf event ring buffer full, dropped %d samples", m.child.Name(), record.LostSamples)
				continue
			}

			var e event.IEventStruct
			e, err = m.child.Decode(em, record.RawSample)
			if err != nil {
				m.logger.Printf("%s\tm.child.decode error:%v", m.child.Name(), err)
				continue
			}

			// 上报数据
			m.Dispatcher(e)
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
				m.logger.Printf("%s\tringbufEventReader received close signal from context.Done().", m.child.Name())
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					m.logger.Printf("%s\tReceived signal, exiting..", m.child.Name())
					return
				}
				errChan <- fmt.Errorf("%s\treading from ringbuf reader: %s", m.child.Name(), err)
				return
			}

			var e event.IEventStruct
			e, err = m.child.Decode(em, record.RawSample)
			if err != nil {
				m.logger.Printf("%s\tm.child.decode error:%v", m.child.Name(), err)
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

// 写入数据，或者上传到远程数据库，写入到其他chan 等。
func (m *Module) Dispatcher(e event.IEventStruct) {
	switch e.EventType() {
	case event.EventTypeOutput:
		if m.conf.GetHex() {
			m.logger.Println(e.StringHex())
		} else {
			m.logger.Println(e.String())
		}
	case event.EventTypeEventProcessor:
		m.processor.Write(e)
	case event.EventTypeModuleData:
		// Save to cache
		m.child.Dispatcher(e)
	}
}

func (m *Module) Close() error {
	m.logger.Printf("%s\tclose", m.child.Name())
	for _, iClose := range m.reader {
		if err := iClose.Close(); err != nil {
			return err
		}
	}
	err := m.processor.Close()
	return err
}
