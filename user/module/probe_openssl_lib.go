package module

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"regexp"
	"strings"
)

func (this *MOpenSSLProbe) detectOpenssl(soPath string) error {
	f, err := os.OpenFile(soPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return errors.New("failed to open the file")
	}
	r, e := elf.NewFile(f)
	if e != nil {
		return errors.New("failed to parse the ELF file succesfully")
	}

	s := r.Section(".rodata")
	if s == nil {
		// not found
		return nil
	}

	sectionSize := int64(s.Offset)

	_, err = f.Seek(0, 0)
	if err != nil {
		return nil
	}

	ret, err := f.Seek(sectionSize, 0)
	if ret != sectionSize || err != nil {
		return nil
	}

	buf := make([]byte, s.Size)
	if buf == nil {
		return nil
	}

	_, err = f.Read(buf)
	if err != nil {
		return nil
	}

	// 按照\x00 拆分  buf
	var slice [][]byte
	if slice = bytes.Split(buf, []byte("\x00")); slice == nil {
		return nil
	}

	dumpStrings := make(map[uint64][]byte, len(slice))
	length := uint64(len(slice))

	var offset uint64

	for i := uint64(0); i < length; i++ {
		if len(slice[i]) == 0 {
			continue
		}

		dumpStrings[offset] = slice[i]

		offset += (uint64(len(slice[i])) + 1)
	}

	// e.g : OpenSSL 1.1.1j  16 Feb 2021
	rex, err := regexp.Compile(`OpenSSL\s(1\.1\.1[a-z]+)\s\s`)
	if err != nil {
		return nil
	}

	versionKey := LinuxDefauleFilename
	for _, v := range dumpStrings {
		if strings.Contains(string(v), "OpenSSL") {
			match := rex.FindStringSubmatch(string(v))
			if match != nil {
				versionKey = match[1]
				break
			}
		}
	}

	// find the sslVersion bpfFile from sslVersionBpfMap
	bpfFile, found := this.sslVersionBpfMap[versionKey]
	if found {
		this.sslBpfFile = bpfFile
		return nil
	}

	// if not found, use default
	bpfFile, _ = this.sslVersionBpfMap[LinuxDefauleFilename]
	this.sslBpfFile = bpfFile
	return nil
}
