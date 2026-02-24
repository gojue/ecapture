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

package openssl

import (
	"debug/elf"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

const (
	// Supported OpenSSL versions (simplified for Phase 4 Plan B)
	Version_1_1_1 = "1.1.1"
	Version_3_0   = "3.0"
	Version_3_1   = "3.1"
)

// Config extends BaseConfig with OpenSSL-specific configuration.
type Config struct {
	*config.BaseConfig
	OpensslPath string `json:"opensslpath"` // Path to libssl.so

	// Capture mode configuration
	CaptureMode string `json:"capturemode"` // "text", "keylog", or "pcap"
	KeylogFile  string `json:"keylogfile"`  // Path to keylog file (for keylog mode)

	// Pcap mode configuration
	PcapFile   string `json:"pcapfile"`   // Path to pcap/pcapng file (for pcap mode)
	Ifname     string `json:"ifname"`     // Network interface name (for pcap mode)
	PcapFilter string `json:"pcapfilter"` // BPF filter expression (for pcap mode)

	// Detection results
	SslVersion      string   `json:"sslversion"`      // Detected OpenSSL version
	IsBoringSSL     bool     `json:"isboringssl"`     // Whether this is BoringSSL
	MasterHookFuncs []string `json:"masterhookfuncs"` // List of master hook functions to attach
	SslBpfFile      string   `json:"sslbpffile"`      // Path to the eBPF object file for the detected OpenSSL version
	IsAndroid       bool     `json:"is_android"`      // Whether the target system is Android (for Android-specific handling)
	AndroidVer      string   `json:"androidver"`      // Android version (for Android-specific handling)
}

// NewConfig creates a new OpenSSL probe configuration.
func NewConfig() *Config {
	return &Config{
		BaseConfig:  config.NewBaseConfig(),
		CaptureMode: "text", // Default to text mode
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return errors.NewConfigurationError("openssl config validation failed", err)
	}

	// Detect OpenSSL library (platform-specific)
	if err := c.detectOpenSSL(); err != nil {
		return errors.NewConfigurationError("openssl detection failed", err)
	}

	// Detect version (platform-specific)
	if err := c.detectOS(); err != nil {
		return errors.NewConfigurationError("openssl version detection failed", err)
	}

	if err := c.getSslBpfFile(c.OpensslPath, c.SslVersion); err != nil {
		return errors.NewConfigurationError("openssl bpf file detection failed", err)
	}

	if err := c.validateConfig(); err != nil {
		return errors.NewConfigurationError("openssl config validation failed", err)
	}

	// Set default interface name if needed (Android-specific)
	c.setDefaultIfname()

	// If unsupported version is detected, users should report it
	// See: https://github.com/gojue/ecapture/issues for reporting new versions

	// Validate capture mode
	if err := c.validateCaptureMode(); err != nil {
		return errors.NewConfigurationError("capture mode validation failed", err)
	}

	return nil
}

func (c *Config) validateConfig() error {
	if c.SslVersion == "" || c.SslBpfFile == "" {
		return fmt.Errorf("unsupported OpenSSL , version: %s, path: %s", c.SslVersion, c.SslBpfFile)
	}
	return nil
}

// validateCaptureMode checks if the capture mode configuration is valid.
func (c *Config) validateCaptureMode() error {
	// Normalize capture mode
	mode := strings.ToLower(c.CaptureMode)
	c.CaptureMode = mode

	switch mode {
	case "text", "":
		// Text mode is the default, no additional validation needed
		c.CaptureMode = "text"
		return nil
	case handlers.ModeKeylog, handlers.ModeKey:
		// Keylog mode requires a keylog file path
		c.CaptureMode = handlers.ModeKeylog
		if c.KeylogFile == "" {
			return fmt.Errorf("keylog mode requires KeylogFile to be set")
		}
		// Check if we can create/write to the keylog file
		dir := filepath.Dir(c.KeylogFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("keylog directory does not exist: %s", dir)
		}
		return nil
	case handlers.ModePcap, handlers.ModePcapng:
		// Pcap mode requires pcap file path and network interface
		c.CaptureMode = handlers.ModePcap
		if c.PcapFile == "" {
			return fmt.Errorf("pcap mode requires PcapFile to be set")
		}
		if c.Ifname == "" {
			return fmt.Errorf("pcap mode requires Ifname (network interface) to be set")
		}
		// Check if pcap directory exists
		dir := filepath.Dir(c.PcapFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("pcap directory does not exist: %s", dir)
		}

		// Validate network interface exists
		if err := c.validateNetworkInterface(); err != nil {
			return err
		}

		// Check TC (Traffic Control) classifier support
		if err := c.checkTCSupport(); err != nil {
			return err
		}

		return nil
	default:
		return fmt.Errorf("unsupported capture mode: %s (supported: text, keylog, pcap)", mode)
	}
}

// IsSupportedVersion checks if the detected version is supported.
func (c *Config) IsSupportedVersion() bool {
	if c.SslVersion != "" {
		return true
	}
	return false
}

// GetBPFFileName returns the eBPF object file name for the detected version.
func (c *Config) GetBPFFileName() string {
	// Return version-specific eBPF file names
	return c.SslBpfFile
}

// Bytes serializes the configuration to JSON.
func (c *Config) Bytes() []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return []byte{}
	}
	return b
}

// validateNetworkInterface checks if the specified network interface exists.
func (c *Config) validateNetworkInterface() error {
	if c.Ifname == "" {
		return nil // Already checked earlier, but just in case
	}

	// Try to get the interface by name
	iface, err := net.InterfaceByName(c.Ifname)
	if err != nil {
		return fmt.Errorf("network interface '%s' not found: %w", c.Ifname, err)
	}

	// Check if interface is up
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("network interface '%s' is not up", c.Ifname)
	}

	return nil
}

// checkTCSupport checks if the system supports TC (Traffic Control) classifier.
// This is a basic check - full TC support validation would require checking kernel modules,
// capabilities, and qdisc configuration, which is done at probe initialization time.
func (c *Config) checkTCSupport() error {
	// Check if /proc/sys/net/core exists (basic networking support)
	if _, err := os.Stat("/proc/sys/net/core"); os.IsNotExist(err) {
		return fmt.Errorf("system networking support not available: /proc/sys/net/core not found")
	}

	// Check if /sys/class/net exists (network device management)
	if _, err := os.Stat("/sys/class/net"); os.IsNotExist(err) {
		return fmt.Errorf("network device management not available: /sys/class/net not found")
	}

	// Check if the interface exists in sysfs
	ifacePath := filepath.Join("/sys/class/net", c.Ifname)
	if _, err := os.Stat(ifacePath); os.IsNotExist(err) {
		return fmt.Errorf("network interface '%s' not found in sysfs", c.Ifname)
	}

	// Note: Full TC classifier support validation (qdisc clsact, eBPF TC programs, etc.)
	// is deferred to probe initialization when eBPF manager attempts to attach.
	// At that point, proper error handling will indicate if TC is not supported.

	return nil
}

// GetCaptureMode returns the capture mode (text, keylog, or pcap).
func (c *Config) GetCaptureMode() string {
	return c.CaptureMode
}

// GetPcapFile returns the pcap file path.
func (c *Config) GetPcapFile() string {
	return c.PcapFile
}

// GetKeylogFile returns the keylog file path.
func (c *Config) GetKeylogFile() string {
	return c.KeylogFile
}

// getSslBpfFile 根据sslVersion参数，获取对应的bpf文件
func (c *Config) getSslBpfFile(soPath, sslVersion string) error {
	defer func() {
		if strings.Contains(c.SslBpfFile, "boringssl") {
			c.IsBoringSSL = true
			c.MasterHookFuncs = []string{MasterKeyHookFuncBoringSSL}
		}
		// TODO detect sslVersion less then 1.1.0 ,  ref # https://github.com/gojue/ecapture/issues/518
		tmpSslVer := c.SslVersion
		if strings.Contains(tmpSslVer, " 1.0.") {
			// no function named SSL_in_before at openssl 1.0.* , and it is a macro definition， so need to change to SSL_state
			for i, hookFunc := range c.MasterHookFuncs {
				if hookFunc == MasterKeyHookFuncSSLBefore {
					c.MasterHookFuncs[i] = MasterKeyHookFuncSSLState
					//c.Logger().Info().Str("openssl version", tmpSslVer).Str("hookFunc", MasterKeyHookFuncSSLState).Str("oldHookFunc", MasterKeyHookFuncSSLBefore).Msg("openssl version is less than 1.0.*")
				}
			}
		}
	}()

	if sslVersion != "" {
		bpfFile, found := sslVersionBpfMap[sslVersion]
		if found {
			//c.Logger().Info().Str("sslVersion", sslVersion).Msg("OpenSSL/BoringSSL version found")
			c.SslBpfFile = bpfFile
			return nil
		}
	}

	verString, err := detectOpenssl(soPath)

	if err != nil && !goerrors.Is(err, ErrProbeOpensslVerNotFound) {
		//c.Logger().Error().Str("soPath", soPath).Err(err).Msg("OpenSSL/BoringSSL version check failed")
		return err
	}

	if goerrors.Is(err, ErrProbeOpensslVerNotFound) {
		// 未找到版本号， try libcrypto.so.x
		if strings.Contains(soPath, "libssl.so.3") {
			//c.Logger().Warn().Err(err).Str("soPath", soPath).Msg("OpenSSL/BoringSSL version not found.")
			//c.Logger().Warn().Msg("Try to detect libcrypto.so.3. If you have doubts, See https://github.com/gojue/ecapture/discussions/675 for more information.")

			// 从 libssl.so.3 中获取 libcrypto.so.3 的路径
			var libcryptoName = "libcrypto.so.3"
			var imd []string
			imd, err = getImpNeeded(soPath)
			if err == nil {
				for _, im := range imd {
					// 匹配 包含 libcrypto.so 字符的动态链接库库名
					if strings.Contains(im, "libcrypto.so") {
						libcryptoName = im
						break
					}
				}
			}
			soPath = strings.Replace(soPath, "libssl.so.3", libcryptoName, 1)
			//c.Logger().Info().Str("soPath", soPath).Str("imported", libcryptoName).Msg("Try to detect imported libcrypto.so ")
			verString, err = detectOpenssl(soPath)
			if err != nil && !goerrors.Is(err, ErrProbeOpensslVerNotFound) {
				//c.Logger().Warn().Err(err).Str("soPath", soPath).Str("imported", libcryptoName).Msgf("OpenSSL(libcrypto.so.3) version not found.%s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideLinux))
				return err
			}
			if goerrors.Is(err, ErrProbeOpensslVerNotFound) {
				//c.Logger().Info().Str("soPath", soPath).Str("imported", libcryptoName).Str("version", verString).Msg("OpenSSL/BoringSSL version found from imported libcrypto.so")
			}
		}
	}

	var bpfFileKey, bpfFile string
	isAndroid := c.IsAndroid
	androidVer := c.AndroidVer
	bpfFileKey = sslVersion
	if verString != "" {
		c.SslVersion = verString
		//c.Logger().Info().Str("origin versionKey", verString).Str("versionKeyLower", verString).Send()
		// find the sslVersion bpfFile from sslVersionBpfMap
		var found bool
		bpfFileKey = verString
		if isAndroid {
			// sometimes,boringssl version always was "boringssl 1.1.1" on android. but offsets are different.
			// see kern/boringssl_a_13_kern.c and kern/boringssl_a_14_kern.c
			// Perhaps we can utilize the Android Version to choose a specific version of boringssl.
			// use the corresponding bpfFile
			bpfFileKey = fmt.Sprintf("boringssl_a_%s", androidVer)
		}
		bpfFile, found = sslVersionBpfMap[bpfFileKey]
		if found {
			c.SslBpfFile = bpfFile
			//c.Logger().Info().Bool("Android", isAndroid).Str("library version", bpfFileKey).Msg("OpenSSL/BoringSSL version found")
			return nil
		} else {
			//c.Logger().Warn().Str("version", bpfFileKey).Err(ErrProbeOpensslVerBytecodeNotFound).Msg("Please send an issue to https://github.com/gojue/ecapture/issues")
		}
	}

	bpfFile = c.autoDetectBytecode(bpfFileKey, soPath, isAndroid)
	c.SslBpfFile = bpfFile

	return nil
}

func detectOpenssl(soPath string) (string, error) {
	f, err := os.OpenFile(soPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("can not open %s, with error:%w", soPath, err)
	}
	r, e := elf.NewFile(f)
	if e != nil {
		return "", fmt.Errorf("parse the ELF file  %s failed, with error:%w", soPath, err)
	}

	switch r.FileHeader.Machine {
	case elf.EM_X86_64:
	case elf.EM_AARCH64:
	default:
		return "", fmt.Errorf("unsupported arch library ,ELF Header Machine is :%s, must be one of EM_X86_64 and EM_AARCH64", r.FileHeader.Machine.String())
	}

	s := r.Section(".rodata")
	if s == nil {
		// not found
		return "", fmt.Errorf("detect openssl version failed, cant read .rodata section from %s", soPath)
	}

	sectionOffset := int64(s.Offset)
	sectionSize := s.Size

	_ = r.Close()

	_, err = f.Seek(0, 0)
	if err != nil {
		return "", err
	}

	ret, err := f.Seek(sectionOffset, 0)
	if ret != sectionOffset || err != nil {
		return "", err
	}

	versionKey := ""

	// e.g : OpenSSL 1.1.1j  16 Feb 2021
	// OpenSSL 3.2.0 23 Nov 2023
	rex, err := regexp.Compile(`(OpenSSL\s\d\.\d\.[0-9a-z]+)`)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024*1024) // 1Mb
	totalReadCount := 0
	for totalReadCount < int(sectionSize) {
		var readCount int
		readCount, err = f.Read(buf)

		if err != nil {
			//c.Logger().Error().Err(err).Msg("read openssl version failed")
			break
		}

		if readCount == 0 {
			break
		}

		match := rex.Find(buf)
		if match != nil {
			versionKey = string(match)
			break
		}

		// Subtracting OpenSslVersionLen from totalReadCount,
		// to cover the edge-case in which openssl version string
		// could be split into two buffers. Subtraction will,
		// makes sure that last 30 bytes of previous buffer are considered.
		totalReadCount += readCount - OpenSslVersionLen

		_, err = f.Seek(sectionOffset+int64(totalReadCount), 0)
		if err != nil {
			break
		}

		clear(buf)

	}

	_ = f.Close()
	//buf = buf[:0]

	if versionKey == "" {
		return "", ErrProbeOpensslVerNotFound
	}

	versionKeyLower := strings.ToLower(versionKey)

	return versionKeyLower, nil
}

func (c *Config) autoDetectBytecode(ver, soPath string, isAndroid bool) string {
	var bpfFile string
	var found bool
	// if not found, use default
	if isAndroid {
		c.SslVersion = AndroidDefaultFilename
		androidVer := c.AndroidVer
		if androidVer != "" {
			bpfFileKey := fmt.Sprintf("boringssl_a_%s", androidVer)
			bpfFile, found = sslVersionBpfMap[bpfFileKey]
			if found {
				return bpfFile
			}
		}
		bpfFile, found = sslVersionBpfMap[AndroidDefaultFilename]
		if !found {
			//c.Logger().Warn().Str("BoringSSL Version", AndroidDefaultFilename).Msg("Can not find Default BoringSSL version")
			return ""
		}
		//c.Logger().Warn().Msgf("OpenSSL/BoringSSL version not found, Automatically selected.%s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideAndroid))
		return bpfFile
	}

	// auto downgrade openssl version
	var isDowngrade bool
	bpfFile, isDowngrade = c.downgradeOpensslVersion(ver, soPath)
	if isDowngrade {
		//c.Logger().Error().Str("OpenSSL Version", ver).Str("bpfFile", bpfFile).Msgf("OpenSSL/BoringSSL version not found, used downgrade version. %s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideLinux))
	} else {
		//c.Logger().Error().Str("OpenSSL Version", ver).Str("bpfFile", bpfFile).Msgf("OpenSSL/BoringSSL version not found, used default version. %s", fmt.Sprintf(OpensslNoticeUsedDefault, OpensslNoticeVersionGuideLinux))
	}

	return bpfFile
}

func getImpNeeded(soPath string) ([]string, error) {
	var importedNeeded []string
	f, err := os.OpenFile(soPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return importedNeeded, fmt.Errorf("can not open %s, with error:%w", soPath, err)
	}

	elfFile, err := elf.NewFile(f)
	if err != nil {
		return importedNeeded, fmt.Errorf("parse the ELF file  %s failed, with error:%w", soPath, err)
	}

	// 打印外部依赖的动态链接库
	is, err := elfFile.DynString(elf.DT_NEEDED)
	//is, err := elfFile.ImportedSymbols()
	if err != nil {
		return importedNeeded, err
	}
	importedNeeded = append(importedNeeded, is...)
	return importedNeeded, nil
}

func (c *Config) downgradeOpensslVersion(ver string, soPath string) (string, bool) {
	var candidates []string
	// 未找到时，逐步截取ver查找最相近的
	for i := len(ver) - 1; i > 0; i-- {
		prefix := ver[:i]

		// 找到所有匹配前缀的key
		for libKey := range sslVersionBpfMap {
			if strings.HasPrefix(libKey, prefix) && isVersionLessOrEqual(libKey, ver) {
				candidates = append(candidates, libKey)
			}
		}

		if len(candidates) > 0 {
			// 按ASCII顺序排序，取最大的
			sort.Strings(candidates)
			return sslVersionBpfMap[candidates[len(candidates)-1]], true
		}
	}
	var bpfFile string
	if strings.Contains(soPath, "libssl.so.3") {
		c.SslVersion = LinuxDefaultFilename30
		bpfFile, _ = sslVersionBpfMap[LinuxDefaultFilename30]
	} else {
		c.SslVersion = LinuxDefaultFilename111
		bpfFile, _ = sslVersionBpfMap[LinuxDefaultFilename111]
	}
	return bpfFile, false
}
