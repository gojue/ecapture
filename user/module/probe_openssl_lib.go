package module

import (
	"bytes"
	"debug/elf"
	"ecapture/user/config"
	"errors"
	"os"
	"regexp"
	"strings"
)

const (
	MaxSupportedOpenSSL111Version = 'r'
	MaxSupportedOpenSSL30Version  = '6'
)

// initOpensslOffset initial BpfMap
func (this *MOpenSSLProbe) initOpensslOffset() {
	this.sslVersionBpfMap = map[string]string{

		// openssl 1.1.1*
		LinuxDefauleFilename: "openssl_1_1_1" + string(MaxSupportedOpenSSL111Version) + "_kern.o",

		// openssl 3.0.*

		// boringssl
		"BoringSSL 1.1.1":      "boringssl_1_1_1_kern.o",
		AndroidDefauleFilename: "boringssl_1_1_1_kern.o",
	}

	for ch := 'a'; ch <= MaxSupportedOpenSSL111Version; ch++ {
		this.sslVersionBpfMap["OpenSSL 1.1.1"+string(ch)] = "openssl_1_1_1" + string(ch) + "_kern.o"
	}

	for ch := '0'; ch <= MaxSupportedOpenSSL30Version; ch++ {
		this.sslVersionBpfMap["OpenSSL 3.0."+string(ch)] = "openssl_3_0_" + string(ch) + "_kern.o"
	}
}

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
		return err
	}

	ret, err := f.Seek(sectionSize, 0)
	if ret != sectionSize || err != nil {
		return err
	}

	buf := make([]byte, s.Size)
	if buf == nil {
		return nil
	}

	_, err = f.Read(buf)
	if err != nil {
		return err
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
	rex, err := regexp.Compile(`(OpenSSL\s\d\.\d\.[0-9a-z]+)`)
	if err != nil {
		return nil
	}

	versionKey := ""
	isAndroid := this.conf.(*config.OpensslConfig).IsAndroid

	for _, v := range dumpStrings {
		if strings.Contains(string(v), "OpenSSL") {
			match := rex.FindStringSubmatch(string(v))
			if match != nil {
				versionKey = match[0]
				break
			}
		}
	}

	this.logger.Printf("versionKey:%s", versionKey)

	var bpfFile string
	var found bool
	if versionKey != "" {
		// find the sslVersion bpfFile from sslVersionBpfMap
		bpfFile, found = this.sslVersionBpfMap[versionKey]
		if found {
			this.sslBpfFile = bpfFile
			return nil
		}
	}

	// if not found, use default
	if isAndroid {
		bpfFile, _ = this.sslVersionBpfMap[AndroidDefauleFilename]
		this.logger.Printf("%s\tOpenSSL/BoringSSL version not found, used default version :%s\n", this.Name(), AndroidDefauleFilename)
	} else {
		bpfFile, _ = this.sslVersionBpfMap[LinuxDefauleFilename]
		this.logger.Printf("%s\tOpenSSL/BoringSSL version not found from shared library file, used default version:%s\n", this.Name(), LinuxDefauleFilename)
	}
	this.sslBpfFile = bpfFile
	return nil
}
