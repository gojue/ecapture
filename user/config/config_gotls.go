// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Copyright © 2022 Hengqi Chen
package config

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	// 46EE50 - 46EDB0
	//
	GoTlsReadFunc = "crypto/tls.(*Conn).Read"

	GoTlsWriteFunc        = "crypto/tls.(*Conn).writeRecordLocked"
	GoTlsMasterSecretFunc = "crypto/tls.(*Config).writeKeyLog"
	// crypto_tls._ptr_Conn.Read
	GoTlsReadFuncArm64 = "crypto_tls._ptr_Conn.Read"
)

var (
	ErrorGoBINNotFound           = errors.New("The executable program (compiled by Golang) was not found")
	ErrorSymbolEmpty             = errors.New("symbol is empty")
	ErrorSymbolNotFound          = errors.New("symbol not found")
	ErrorSymbolNotFoundFromTable = errors.New("symbol not found from table")
	ErrorNoRetFound              = errors.New("no RET instructions found")
	ErrorNoRetFoundFromSymTabFun = errors.New("no RET instructions found from golang symbol table with Fun")
)

// From go/src/debug/gosym/pclntab.go
const (
	go12magic  = 0xfffffffb
	go116magic = 0xfffffffa
	go118magic = 0xfffffff0
	go120magic = 0xfffffff1
)

// Select the magic number based on the Go version
func magicNumber(goVersion string) []byte {
	bs := make([]byte, 4)
	var magic uint32
	if strings.Compare(goVersion, "go1.20") >= 0 {
		magic = go120magic
	} else if strings.Compare(goVersion, "go1.18") >= 0 {
		magic = go118magic
	} else if strings.Compare(goVersion, "go1.16") >= 0 {
		magic = go116magic
	} else {
		magic = go12magic
	}
	binary.LittleEndian.PutUint32(bs, magic)
	return bs
}

type FuncOffsets struct {
	Start   uint64
	Returns []uint64
}

// GoTLSConfig represents configuration for Go SSL probe
type GoTLSConfig struct {
	eConfig
	Path                  string    `json:"path"`       // golang application path to binary built with Go toolchain.
	PcapFile              string    `json:"pcapFile"`   // pcapFile  the  raw  packets  to file rather than parsing and printing them out.
	KeylogFile            string    `json:"keylogFile"` // keylogFile  The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.
	Model                 string    `json:"model"`      // model  such as : text, pcapng/pcap, key/keylog.
	Ifname                string    `json:"ifName"`     // (TC Classifier) Interface name on which the probe will be attached.
	PcapFilter            string    `json:"pcapFilter"` // pcap filter
	goElfArch             string    //
	goElf                 *elf.File //
	buildinfo             *buildinfo.BuildInfo
	ReadTlsAddrs          []int
	GoTlsWriteAddr        uint64
	GoTlsMasterSecretAddr uint64
	IsPieBuildMode        bool
	goSymTab              *gosym.Table
}

// NewGoTLSConfig creates a new config for Go SSL
func NewGoTLSConfig() *GoTLSConfig {
	gc := &GoTLSConfig{}
	gc.PerCpuMapSize = DefaultMapSizePerCpu
	return gc
}

func (gc *GoTLSConfig) Check() error {
	var err error
	if gc.Path == "" {
		return ErrorGoBINNotFound
	}

	_, err = gc.checkModel()
	if err != nil {
		return err
	}
	_, err = os.Stat(gc.Path)
	if err != nil {
		return err
	}

	// Read the build information of the Go application
	gc.buildinfo, err = buildinfo.ReadFile(gc.Path)
	if err != nil {
		return err
	}

	var goElf *elf.File
	goElf, err = elf.Open(gc.Path)
	if err != nil {
		return err
	}

	var goElfArch string
	switch goElf.FileHeader.Machine.String() {
	case elf.EM_AARCH64.String():
		goElfArch = "arm64"
	case elf.EM_X86_64.String():
		goElfArch = "amd64"
	default:
		goElfArch = "unsupport_arch"
	}

	if goElfArch != runtime.GOARCH {
		err = fmt.Errorf("Go Application not match, want:%s, have:%s", runtime.GOARCH, goElfArch)
		return err
	}
	switch goElfArch {
	case "amd64":
	case "arm64":
	default:
		return fmt.Errorf("unsupport CPU arch :%s", goElfArch)
	}
	gc.goElfArch = goElfArch
	gc.goElf = goElf
	// If built with PIE and stripped, gopclntab is
	// unlabeled and nested under .data.rel.ro.
	for _, bs := range gc.buildinfo.Settings {
		if bs.Key == "-buildmode" {
			if bs.Value == "pie" {
				gc.IsPieBuildMode = true
			}
			break
		}
	}
	if gc.IsPieBuildMode {
		gc.goSymTab, err = gc.ReadTable()
		if err != nil {
			return err
		}
		fun := gc.goSymTab.LookupFunc(GoTlsWriteFunc)
		if fun != nil {
			gc.GoTlsWriteAddr = fun.Entry
		}
		fun = gc.goSymTab.LookupFunc(GoTlsMasterSecretFunc)
		if fun != nil {
			gc.GoTlsMasterSecretAddr = fun.Entry
		}
		gc.ReadTlsAddrs, err = gc.findRetOffsetsPie(GoTlsReadFunc)
		if err != nil {
			return err
		}
	} else {
		gc.ReadTlsAddrs, err = gc.findRetOffsets(GoTlsReadFunc)
		if err != nil {
			return err
		}
	}
	return err
}

func (gc *GoTLSConfig) findRetOffsetsPie(symbolName string) ([]int, error) {
	var offsets []int
	var err error

	fun := gc.goSymTab.LookupFunc(symbolName)
	if fun == nil {
		return nil, ErrorSymbolNotFoundFromTable
	}

	//fmt.Printf("found in %s, entry:%x, end:%x , end-entry:%x\n", fun.Name, fun.Entry, fun.End, fun.End-fun.Entry)
	offsets, err = gc.findFuncOffsetBySymfun(fun, gc.goElf)
	return offsets, err
}

// FindRetOffsets searches for the addresses of all RET instructions within
// the instruction set associated with the specified symbol in an ELF program.
// It is used for mounting uretprobe programs for Golang programs,
// which are actually mounted via uprobe on these addresses.
func (gc *GoTLSConfig) findRetOffsets(symbolName string) ([]int, error) {
	var err error
	var allSymbs []elf.Symbol

	goSymbs, _ := gc.goElf.Symbols()
	if len(goSymbs) > 0 {
		allSymbs = append(allSymbs, goSymbs...)
	}

	goDynamicSymbs, _ := gc.goElf.DynamicSymbols()
	if len(goDynamicSymbs) > 0 {
		allSymbs = append(allSymbs, goDynamicSymbs...)
	}

	if len(allSymbs) == 0 {
		return nil, ErrorSymbolEmpty
	}

	var found bool
	var symbol elf.Symbol
	for _, s := range allSymbs {
		if s.Name == symbolName {
			symbol = s
			found = true
			break
		}
	}

	if !found {
		return nil, ErrorSymbolNotFound
	}

	section := gc.goElf.Sections[symbol.Section]

	var elfText []byte
	elfText, err = section.Data()
	if err != nil {
		return nil, err
	}

	start := symbol.Value - section.Addr
	end := start + symbol.Size

	var offsets []int
	var instHex []byte
	instHex = elfText[start:end]
	offsets, _ = gc.decodeInstruction(instHex)
	if len(offsets) == 0 {
		return offsets, ErrorNoRetFound
	}
	return offsets, nil
}

func (gc *GoTLSConfig) checkModel() (string, error) {
	var m string
	var e error
	switch gc.Model {
	case TlsCaptureModelKeylog, TlsCaptureModelKey:
		m = TlsCaptureModelKey
	case TlsCaptureModelPcap, TlsCaptureModelPcapng:
		m = TlsCaptureModelPcap
		if gc.Ifname == "" {
			return "", errors.New("'pcap' model used, please used -i flag to set ifname value.")
		}
		fmt.Println(gc.Ifname)
	default:
		m = TlsCaptureModelText
	}
	return m, e
}

func (gc *GoTLSConfig) ReadTable() (*gosym.Table, error) {
	sectionLabel := ".data.rel.ro"
	section := gc.goElf.Section(sectionLabel)
	if section == nil {
		// binary may be built with -pie
		sectionLabel = ".gopclntab"
		section = gc.goElf.Section(sectionLabel)
		if section == nil {
			return nil, fmt.Errorf("could not read section %s from %s ", sectionLabel, gc.Path)
		}
	}
	tableData, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("found section but could not read %s from %s ", sectionLabel, gc.Path)
	}

	// Find .gopclntab by magic number even if there is no section label
	magic := magicNumber(gc.buildinfo.GoVersion)
	pclntabIndex := bytes.Index(tableData, magic)
	//fmt.Printf("buildinfo :%v, magic:%x, pclntabIndex:%d offset:%x , section:%v \n", gc.buildinfo, magic, pclntabIndex, section.Offset, section)
	if pclntabIndex < 0 {
		return nil, fmt.Errorf("could not find magic number in %s ", gc.Path)
	}
	tableData = tableData[pclntabIndex:]
	addr := gc.goElf.Section(".text").Addr
	lineTable := gosym.NewLineTable(tableData, addr)
	symTable, err := gosym.NewTable([]byte{}, lineTable)
	if err != nil {
		return nil, ErrorSymbolNotFoundFromTable
	}
	return symTable, nil
}

func (gc *GoTLSConfig) findFuncOffsetBySymfun(f *gosym.Func, elfF *elf.File) ([]int, error) {
	var offsets []int
	var err error

	for _, prog := range elfF.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		// For more info on this calculation: stackoverflow.com/a/40249502
		/*
		 ida :  		 start : 46EE50, end : 46F258   , len :0x408
		 elf info:       start : 46ed30, end :         ,  len: 0x3B0,  0x58

		*/
		if prog.Vaddr <= f.Value && f.Value < (prog.Vaddr+prog.Memsz) {
			funcLen := f.End - f.Entry
			fmt.Printf("name :%s, f.Value:%x, f.Entry:%x, f.End:%x, funcLen:%X \n ", f.Name, f.Value, f.Entry, f.End, funcLen)
			data := make([]byte, funcLen)
			_, err = prog.ReadAt(data, int64(f.Value-prog.Vaddr))
			if err != nil {
				return offsets, fmt.Errorf("finding function return: %w", err)
			}

			offsets, err = gc.decodeInstruction(data)
			if err != nil {
				return offsets, fmt.Errorf("finding function return: %w", err)
			}
			for i, offset := range offsets {
				offsets[i] = int(f.Entry) + offset
			}
			return offsets, nil
		}
	}
	return offsets, ErrorNoRetFoundFromSymTabFun
}
