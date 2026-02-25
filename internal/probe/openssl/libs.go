package openssl

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

const (
	// 备选 HOOK的函数  SSL_is_init_finished \ SSL_get_wbio \ SSL_write
	MasterKeyHookFuncOpenSSL = "SSL_write"

	/*
		在boringSSL类库里，SSL_write函数调用了 SSL_do_handshake ，
		SSL_do_handshake 函数执行时，当前SSL链接握手可能还未完成，且
	*/
	// 2022-12-16 改为 SSL_in_init
	MasterKeyHookFuncBoringSSL = "SSL_in_init"
	MasterKeyHookFuncSSLBefore = "SSL_in_before"
	MasterKeyHookFuncSSLState  = "SSL_state"
)

var (
	/*
	* 为了读取到TLS握手完成后的client_random等密钥，必需要选择一个合适的HOOK函数。
	* SSL_write\SSL_read时，TLS握手是建立完成的，但调用过于频繁，会带来性能问题，参见https://github.com/gojue/ecapture/issues/463
	* 综合来看，合适的HOOK函数需要满足以下几个条件:
	* 1. 函数是在TLS握手完成后调用
	* 2. 函数名在动态链接库的符号表中是导出状态
	* 3. 函数是低频调用
	*
	* 在 openssl 类库中，以客户端角色调用 `SSL_connect` 或者以服务端角色 `SSL_accept` ，最终都会进入 `ssl/statem/statem.c` 的 `state_machine` 函数进行TLS握手。
	* 所以，可选范围是在这个函数内以大写`SSL`开头的函数。
	* 当使用openssl的方式为`同步`调用时，TLS握手成功会返回1，也就是`ret = 1`，即需要在这个变量赋值后，被调用的函数，才能拿到符合要求的内存数据。 `state_machine`函数内符合要求的就只有`SSL_get_wbio`了。
	* 当使用openssl的方式为`异步`调用时，还需要增加`SSL_in_before`函数。
	 */
	masterKeyHookFuncs = []string{
		"SSL_get_wbio", // openssl
		//"SSL_is_init",  // boringssl
		// 备用HOOK 函数
		//"SSL_is_init_finished",
		MasterKeyHookFuncSSLBefore,
		"SSL_do_handshake",
	}
)

var defaultSoPath = "/lib/x86_64-linux-gnu"

const (
	LinuxDefaultFilename102 = "linux_default_1_0_2"
	LinuxDefaultFilename110 = "linux_default_1_1_0"
	LinuxDefaultFilename111 = "linux_default_1_1_1"
	LinuxDefaultFilename30  = "linux_default_3_0"
	LinuxDefaultFilename31  = "linux_default_3_0"
	LinuxDefaultFilename320 = "linux_default_3_2"
	LinuxDefaultFilename330 = "linux_default_3_3"
	LinuxdDfaultFilename340 = "linux_default_3_4"
	AndroidDefaultFilename  = "android_default"

	OpenSslVersionLen = 30 // openssl version string length
)

const (
	MaxSupportedOpenSSL102Version = 'u'
	MaxSupportedOpenSSL110Version = 'l'
	MaxSupportedOpenSSL111Version = 'w'
	SupportedOpenSSL30Version12   = 12 // openssl 3.0.12
	MaxSupportedOpenSSL30Version  = 17
	MaxSupportedOpenSSL31Version  = 8
	SupportedOpenSSL32Version2    = 2 // openssl 3.2.0 ~ 3.2.2
	SupportedOpenSSL32Version3    = 3 // openssl 3.2.3
	SupportedOpenSSL32Version4    = 5 // openssl 3.2.5
	MaxSupportedOpenSSL32Version  = 3 // openssl 3.2.3 ~ newer
	SupportedOpenSSL33Version1    = 1 // openssl 3.3.0 ~ 3.3.1
	SupportedOpenSSL33Version2    = 2 // openssl 3.3.2
	MaxSupportedOpenSSL33Version  = 4 // openssl 3.3.4
	SupportedOpenSSL34Version0    = 0 // openssl 3.4.0
	MaxSupportedOpenSSL34Version  = 2 // openssl 3.4.2
	SupportedOpenSSL35Version0    = 4 // openssl 3.5.0 ~ 3.5.4
	MaxSupportedOpenSSL35Version  = 4 // openssl 3.5.4
)

var (
	ErrProbeOpensslVerNotFound         = errors.New("OpenSSL/BoringSSL version not found")
	ErrProbeOpensslVerBytecodeNotFound = errors.New("OpenSSL/BoringSSL version bytecode not found")
	OpensslNoticeVersionGuideAndroid   = "\"--ssl_version='boringssl_a_13'\" , \"--ssl_version='boringssl_a_14'\""
	OpensslNoticeVersionGuideLinux     = "\"--ssl_version='openssl x.x.x'\", support openssl 1.0.x, 1.1.x, 3.x or newer"
	OpensslNoticeUsedDefault           = "If you want to use the specific version, please set the sslVersion parameter with %s, or use \"ecapture tls --help\" for more help."
)

// isVersionLessOrEqual 比较两个版本号字符串，返回 v1 <= v2
func isVersionLessOrEqual(v1, v2 string) bool {
	// 提取版本号部分，去掉 "openssl " 前缀
	version1 := strings.TrimPrefix(v1, "openssl ")
	version2 := strings.TrimPrefix(v2, "openssl ")

	// 按点分割版本号
	parts1 := strings.Split(version1, ".")
	parts2 := strings.Split(version2, ".")

	// 比较每个部分
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1Str, p2Str string
		if i < len(parts1) {
			p1Str = parts1[i]
		} else {
			p1Str = "0"
		}
		if i < len(parts2) {
			p2Str = parts2[i]
		} else {
			p2Str = "0"
		}

		// 分别提取数字和字母部分
		num1, suffix1 := extractVersionPart(p1Str)
		num2, suffix2 := extractVersionPart(p2Str)

		// 先比较数字部分
		if num1 < num2 {
			return true
		}
		if num1 > num2 {
			return false
		}

		// 数字相等时比较字母后缀
		if suffix1 < suffix2 {
			return true
		}
		if suffix1 > suffix2 {
			return false
		}
	}

	return true // 相等时返回 true
}

// extractVersionPart 从版本号部分中提取数字和字母后缀
func extractVersionPart(s string) (int, string) {
	var numStr strings.Builder
	var suffix string

	// 提取开头的数字部分
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		numStr.WriteByte(s[i])
		i++
	}

	// 剩余部分作为后缀
	if i < len(s) {
		suffix = s[i:]
	}

	num := 0
	if numStr.Len() > 0 {
		// 忽略转换错误，因为我们已经确保了是数字
		num, _ = strconv.Atoi(numStr.String())
	}

	return num, suffix
}

var sslVersionBpfMap map[string]string // bpf map key: ssl version, value: bpf map key

// init initial BpfMap
func init() {

	if runtime.GOARCH == "arm64" {
		defaultSoPath = "/lib/aarch64-linux-gnu"
	}

	sslVersionBpfMap = map[string]string{
		// openssl 1.0.2*
		LinuxDefaultFilename102: "openssl_1_0_2a_kern.o",

		// openssl 1.1.0*
		LinuxDefaultFilename110: "openssl_1_1_0a_kern.o",

		// openssl 1.1.1*
		LinuxDefaultFilename111: "openssl_1_1_1j_kern.o",

		// openssl 3.0.* and openssl 3.1.*
		LinuxDefaultFilename30: "openssl_3_0_0_kern.o",

		// openssl 3.2.*
		LinuxDefaultFilename320: "openssl_3_2_0_kern.o",

		// boringssl
		// git repo: https://android.googlesource.com/platform/external/boringssl/+/refs/heads/android12-release
		"boringssl 1.1.1":      "boringssl_a_13_kern.o",
		"boringssl_a_13":       "boringssl_a_13_kern.o",
		"boringssl_a_14":       "boringssl_a_14_kern.o",
		"boringssl_a_15":       "boringssl_a_15_kern.o",
		"boringssl_a_16":       "boringssl_a_16_kern.o",
		AndroidDefaultFilename: "boringssl_a_13_kern.o",

		// non-Android boringssl
		// "boringssl na" is a special version for non-android
		// git repo: https://github.com/google/boringssl
		"boringssl na": "boringssl_na_kern.o",
	}

	// in openssl source files, there are 4 offset groups for all 1.1.1* version.
	// group a : 1.1.1a
	sslVersionBpfMap["openssl 1.1.1a"] = "openssl_1_1_1a_kern.o"

	// group b : 1.1.1b-1.1.1c
	sslVersionBpfMap["openssl 1.1.1b"] = "openssl_1_1_1b_kern.o"
	sslVersionBpfMap["openssl 1.1.1c"] = "openssl_1_1_1b_kern.o"

	// group c : 1.1.1d-1.1.1i
	for ch := 'd'; ch <= 'i'; ch++ {
		sslVersionBpfMap["openssl 1.1.1"+string(ch)] = "openssl_1_1_1d_kern.o"
	}

	// group e : 1.1.1j-1.1.1s
	for ch := 'j'; ch <= MaxSupportedOpenSSL111Version; ch++ {
		sslVersionBpfMap["openssl 1.1.1"+string(ch)] = "openssl_1_1_1j_kern.o"
	}

	// openssl 3.0.0 - 3.0.15
	for ch := 0; ch <= MaxSupportedOpenSSL30Version; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.0.%d", ch)] = "openssl_3_0_0_kern.o"
	}

	// support openssl 3.0.12
	// 2025-08-23  3.0.12 is a special version, the offset is different from 3.0.0 - 3.0.11, and 3.0.13 - 3.0.17, so we need to special support it
	sslVersionBpfMap[fmt.Sprintf("openssl 3.0.%d", SupportedOpenSSL30Version12)] = "openssl_3_0_12_kern.o"

	// openssl 3.1.0 - 3.1.8
	for ch := 0; ch <= MaxSupportedOpenSSL31Version; ch++ {
		// The OpenSSL 3.0 series is the same as the 3.1 series of offsets
		sslVersionBpfMap[fmt.Sprintf("openssl 3.1.%d", ch)] = "openssl_3_1_0_kern.o"
	}

	// openssl 3.2.0
	for ch := 0; ch <= SupportedOpenSSL32Version2; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", ch)] = "openssl_3_2_0_kern.o"
	}

	// openssl 3.2.3
	sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", SupportedOpenSSL32Version3)] = "openssl_3_2_3_kern.o"
	// openssl 3.2.5
	sslVersionBpfMap[fmt.Sprintf("openssl 3.2.%d", SupportedOpenSSL32Version4)] = "openssl_3_2_4_kern.o"

	// openssl 3.3.0 - 3.3.1
	for ch := 0; ch <= SupportedOpenSSL33Version1; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_0_kern.o"
	}

	// openssl 3.3.2
	for ch := 2; ch <= SupportedOpenSSL33Version2; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_2_kern.o"
	}

	// openssl 3.3.4
	for ch := 3; ch <= MaxSupportedOpenSSL33Version; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.3.%d", ch)] = "openssl_3_3_3_kern.o"
	}

	// openssl 3.4.0
	for ch := 0; ch <= SupportedOpenSSL34Version0; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.4.%d", ch)] = "openssl_3_4_0_kern.o"
	}

	// openssl 3.4.1
	for ch := 1; ch <= MaxSupportedOpenSSL34Version; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.4.%d", ch)] = "openssl_3_4_1_kern.o"
	}

	// openssl 3.5.0
	for ch := 0; ch <= SupportedOpenSSL35Version0; ch++ {
		sslVersionBpfMap[fmt.Sprintf("openssl 3.5.%d", ch)] = "openssl_3_5_0_kern.o"
	}

	// openssl 1.1.0a - 1.1.0l
	for ch := 'a'; ch <= MaxSupportedOpenSSL110Version; ch++ {
		sslVersionBpfMap["openssl 1.1.0"+string(ch)] = "openssl_1_1_0a_kern.o"
	}

	// openssl 1.0.2a - 1.0.2u
	for ch := 'a'; ch <= MaxSupportedOpenSSL102Version; ch++ {
		sslVersionBpfMap["openssl 1.0.2"+string(ch)] = "openssl_1_0_2a_kern.o"
	}
}
