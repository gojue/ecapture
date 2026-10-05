package gotls

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"

	"errors"
)

// FindRetOffsets searches for the addresses of all RET instructions within
// the instruction set associated with the specified symbol in an ELF program.
// It is used for mounting uretprobe programs for Golang programs,
// which are actually mounted via uprobe on these addresses.
func (c *Config) findRetOffsets(symbolName string) ([]int, error) {
	var err error
	var allSymbs []elf.Symbol

	goSymbs, _ := c.goElf.Symbols()
	if len(goSymbs) > 0 {
		allSymbs = append(allSymbs, goSymbs...)
	}
	goDynamicSymbs, _ := c.goElf.DynamicSymbols()
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

	section := c.goElf.Sections[symbol.Section]

	var elfText []byte
	elfText, err = section.Data()
	if err != nil {
		return nil, err
	}

	start := symbol.Value - section.Addr
	end := start + symbol.Size

	var offsets []int
	var instHex = elfText[start:end]
	offsets, _ = decodeInstruction(instHex)
	if len(offsets) == 0 {
		return offsets, ErrorNoRetFound
	}

	address := symbol.Value
	for _, prog := range c.goElf.Progs {
		// Skip uninteresting segments.
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= symbol.Value && symbol.Value < (prog.Vaddr+prog.Memsz) {
			// stackoverflow.com/a/40249502
			address = symbol.Value - prog.Vaddr + prog.Off
			break
		}
	}
	for i, offset := range offsets {
		offsets[i] = int(address) + offset
	}
	return offsets, nil
}

func (c *Config) ReadTable() (*gosym.Table, error) {
	sectionLabel := ".gopclntab"
	section := c.goElf.Section(sectionLabel)
	if section == nil {
		// binary may be built with -pie
		sectionLabel = ".data.rel.ro.gopclntab"
		section = c.goElf.Section(sectionLabel)
		if section == nil {
			sectionLabel = ".data.rel.ro"
			section = c.goElf.Section(sectionLabel)
			if section == nil {
				return nil, fmt.Errorf("could not read section %s from %s ", sectionLabel, c.ElfPath)
			}
		}
	}
	tableData, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("found section but could not read %s from %s ", sectionLabel, c.ElfPath)
	}
	// Find .gopclntab by magic number even if there is no section label
	magic := magicNumber(c.BuildInfo.GoVersion)
	pclntabIndex := bytes.Index(tableData, magic)
	if pclntabIndex < 0 {
		return nil, fmt.Errorf("could not find magic number in %s ", c.ElfPath)
	}
	tableData = tableData[pclntabIndex:]
	var addr uint64
	{
		// get textStart from pclntable
		// please see https://go-review.googlesource.com/c/go/+/366695
		// tableData
		ptrSize := uint32(tableData[7])
		if ptrSize == 4 {
			addr = uint64(binary.LittleEndian.Uint32(tableData[8+2*ptrSize:]))
		} else {
			addr = binary.LittleEndian.Uint64(tableData[8+2*ptrSize:])
		}
	}
	lineTable := gosym.NewLineTable(tableData, addr)
	symTable, err := gosym.NewTable([]byte{}, lineTable)
	if err != nil {
		return nil, ErrorSymbolNotFoundFromTable
	}
	return symTable, nil
}

func (c *Config) findRetOffsetsPie(lfunc string) ([]int, error) {
	var offsets []int
	var address uint64
	var err error
	address, err = c.findPieSymbolAddr(lfunc)
	if err != nil {
		return offsets, err
	}
	f := c.goSymTab.LookupFunc(lfunc)
	funcLen := f.End - f.Entry
	for _, prog := range c.goElf.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		// via https://github.com/golang/go/blob/a65a2bbd8e58cd77dbff8a751dbd6079424beb05/src/cmd/internal/objfile/elf.go#L174
		data := make([]byte, funcLen)
		_, err = prog.ReadAt(data, int64(address-prog.Vaddr))
		if err != nil {
			return offsets, fmt.Errorf("finding function return: %w", err)
		}
		offsets, err = decodeInstruction(data)
		if err != nil {
			return offsets, fmt.Errorf("finding function return: %w", err)
		}
		for i, offset := range offsets {
			offsets[i] = int(address) + offset
		}
		return offsets, nil
	}
	return offsets, errors.New("cant found gotls symbol offsets")
}

func (c *Config) findPieSymbolAddr(lfunc string) (uint64, error) {
	f := c.goSymTab.LookupFunc(lfunc)
	if f == nil {
		return 0, ErrorNoFuncFoundFromSymTabFun
	}
	return f.Value, nil
}

func (c *Config) findSymbolAddr(lfunc string) (uint64, error) {
	f := c.goSymTab.LookupFunc(lfunc)
	if f == nil {
		return 0, ErrorNoFuncFoundFromSymTabFun
	}

	textSect := c.goElf.Section(".text")
	if textSect == nil {
		return 0, ErrorTextSectionNotFound
	}
	textOffset, err := symbolTextOffset(f.Entry, textSect)
	if err != nil {
		return 0, fmt.Errorf("finding %s address: %w", lfunc, err)
	}
	return textSect.Offset + textOffset, nil
}

// symbolTextOffset normalizes gosym function entries to an offset within the
// ELF .text section. Go 1.26 reports entries relative to textStart for some
// binaries, while older toolchains report virtual addresses. Supporting both
// forms prevents unsigned underflow when calculating a uprobe file offset.
func symbolTextOffset(entry uint64, textSect *elf.Section) (uint64, error) {
	if textSect == nil {
		return 0, ErrorTextSectionNotFound
	}
	if entry >= textSect.Addr && entry-textSect.Addr < textSect.Size {
		return entry - textSect.Addr, nil
	}
	if entry < textSect.Size {
		return entry, nil
	}
	return 0, fmt.Errorf("symbol entry %#x is outside .text [%#x, %#x) and relative size %#x",
		entry, textSect.Addr, textSect.Addr+textSect.Size, textSect.Size)
}

func (c *Config) findSymbolRetOffsets(lfunc string) ([]int, error) {
	f := c.goSymTab.LookupFunc(lfunc)
	if f == nil {
		return nil, ErrorNoFuncFoundFromSymTabFun
	}

	textSect := c.goElf.Section(".text")
	if textSect == nil {
		return nil, ErrorTextSectionNotFound
	}
	textData, err := textSect.Data()
	if err != nil {
		return nil, err
	}

	start, err := symbolTextOffset(f.Entry, textSect)
	if err != nil {
		return nil, fmt.Errorf("finding %s return offsets: %w", lfunc, err)
	}
	end := start + (f.End - f.Entry)

	if end <= start || start > textSect.Size || end > textSect.Size {
		return nil, fmt.Errorf("invalid function range start: %d, end: %d", start, end)
	}

	offsets, err := decodeInstruction(textData[start:end])
	if err != nil {
		return nil, err
	}
	address := textSect.Offset + start
	for i, offset := range offsets {
		offsets[i] = int(address) + offset
	}
	return offsets, nil
}
