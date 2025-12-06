## 背景介绍
在eCapture社区的issue 463：[TLS 模式下，对被检测程序的性能影响](https://github.com/gojue/ecapture/issues/463)提到，eCapture启用后，对程序带来较大性能影响。


## 解决思路
选择低频的、有符号表导出的、可取密钥的函数进行HOOK。
参见 [PR 471](https://github.com/gojue/ecapture/pull/471)

## 环境搭建

### TLS Server
1. 在ubuntu 22.04 上执行sudo apt install nginx
2. 开启SSL 443的服务(这里我以我的博客域名为例)
3. 在本目录，执行make，编译测试的客户端进程

## 执行测试

### 原生测试
```shell
time ./openssl_client

real	0m5.677s
user	0m3.088s
sys	0m2.565s
```

#### 启用eCapture后测试
**运行eCapture**
新开一个终端，打开eCapture的`keylog`模式
```shell
sudo bin/ecapture tls -m keylog
[sudo] password for cfc4n:
tls_2024/01/27 13:42:55 ECAPTURE :: ecapture Version : linux_aarch64:0.7.2-20240104-f368e82:[CORE]
tls_2024/01/27 13:42:55 ECAPTURE :: Pid Info : 124787
tls_2024/01/27 13:42:55 ECAPTURE :: Kernel Info : 5.15.131
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	module initialization
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	master key keylogger: ecapture_openssl_key.og
tls_2024/01/27 13:42:55 ECAPTURE ::	Module.Run()
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	Keylog MODEL
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	OpenSSL/BoringSSL version not found from shared library file, used default version:linux_default_3_0
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	HOOK type:2, binrayPath:/usr/lib/aarch64-linux-gnu/libssl.so.3
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	Hook masterKey function:[SSL_get_wbio SSL_in_before]
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	target all process.
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	target all users.
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	BPF bytecode filename:user/bytecode/openssl_3_0_0_kern.o
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	perfEventReader created. mapSize:4 MB
tls_2024/01/27 13:42:55 EBPFProbeOPENSSL	module started successfully.
tls_2024/01/27 13:42:55 ECAPTURE :: 	start 1 modules
tls_2024/01/27 13:42:59 EBPFProbeOPENSSL	TLS1_2_VERSION: save CLIENT_RANDOM 8516901707503cfcfb0b63d02adc5deba9f7bc3e64418212f4a9c7b0c4007cca to file success, 176 bytes
^Ctls_2024/01/27 13:43:15 EBPFProbeOPENSSL	close.
tls_2024/01/27 13:43:15 EBPFProbeOPENSSL	close
```

**运行测试程序**
```shell
time ./openssl_client

real	0m7.133s
user	0m4.735s
sys	0m2.394s
```

### 结果
可以看到，当使用`keylog`模式后，耗时从30秒下降到7秒。