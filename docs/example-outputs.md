# eCapture Example Outputs

This document contains detailed example outputs from various eCapture modes and modules. For a quick start overview, see the [README](../README.md).

## TLS Module — Text Mode

### Command

```bash
sudo ecapture tls
```

### Full Output

```
2024-09-15T11:51:31Z INF AppName="eCapture(旁观者)"
2024-09-15T11:51:31Z INF HomePage=https://ecapture.cc
2024-09-15T11:51:31Z INF Repository=https://github.com/gojue/ecapture
2024-09-15T11:51:31Z INF Author="CFC4N <cfc4ncs@gmail.com>"
2024-09-15T11:51:31Z INF Description="Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supported on Linux/Android kernels for amd64/arm64."
2024-09-15T11:51:31Z INF Version=linux_arm64:0.8.6-20240915-d87ae48:5.15.0-113-generic
2024-09-15T11:51:31Z INF Listen=localhost:28256
2024-09-15T11:51:31Z INF eCapture running logs logger=
2024-09-15T11:51:31Z INF the file handler that receives the captured event eventCollector=
2024-09-15T11:51:31Z INF listen=localhost:28256
2024-09-15T11:51:31Z INF https server starting...You can update the configuration file via the HTTP interface.
2024-09-15T11:51:31Z WRN ========== module starting. ==========
2024-09-15T11:51:31Z INF Kernel Info=5.15.152 Pid=233698
2024-09-15T11:51:31Z INF BTF bytecode mode: CORE. btfMode=0
2024-09-15T11:51:31Z INF master key keylogger has been set. eBPFProgramType=Text keylogger=
2024-09-15T11:51:31Z INF module initialization. isReload=false moduleName=EBPFProbeOPENSSL
2024-09-15T11:51:31Z INF Module.Run()
2024-09-15T11:51:31Z WRN OpenSSL/BoringSSL version not found from shared library file, used default version OpenSSL Version=linux_default_3_0
2024-09-15T11:51:31Z INF Hook masterKey function ElfType=2 Functions=["SSL_get_wbio","SSL_in_before","SSL_do_handshake"] binrayPath=/usr/lib/aarch64-linux-gnu/libssl.so.3
2024-09-15T11:51:31Z INF target all process.
2024-09-15T11:51:31Z INF target all users.
2024-09-15T11:51:31Z INF setupManagers eBPFProgramType=Text
2024-09-15T11:51:31Z INF BPF bytecode file is matched. bpfFileName=user/bytecode/openssl_3_0_0_kern_core.o
2024-09-15T11:51:32Z INF perfEventReader created mapSize(MB)=4
2024-09-15T11:51:32Z INF perfEventReader created mapSize(MB)=4
2024-09-15T11:51:32Z INF module started successfully. isReload=false moduleName=EBPFProbeOPENSSL
2024-09-15T11:51:53Z ??? UUID:233851_233851_curl_5_1_172.16.71.1:51837, Name:HTTP2Request, Type:2, Length:304

Frame Type	=>	SETTINGS

Frame Type	=>	WINDOW_UPDATE

Frame Type	=>	HEADERS
header field ":method" = "GET"
header field ":path" = "/"
header field ":scheme" = "https"
header field ":authority" = "google.com"
header field "user-agent" = "curl/7.81.0"
header field "accept" = "*/*"

Frame Type	=>	SETTINGS

2024-09-15T11:51:53Z ??? UUID:233851_233851_curl_5_0_172.16.71.1:51837, Name:HTTP2Response, Type:4, Length:1160

Frame Type	=>	SETTINGS

Frame Type	=>	WINDOW_UPDATE

Frame Type	=>	SETTINGS

Frame Type	=>	HEADERS
header field ":status" = "301"
header field "location" = "https://www.google.com/"
header field "content-type" = "text/html; charset=UTF-8"
header field "content-security-policy-report-only" = "object-src 'none';base-uri 'self';script-src 'nonce-qvZZ0XreBfeqRnUEV1WoYw' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp"
header field "date" = "Sun, 15 Sep 2024 11:51:52 GMT"
header field "expires" = "Tue, 15 Oct 2024 11:51:52 GMT"
header field "cache-control" = "public, max-age=2592000"
header field "server" = "gws"
header field "content-length" = "220"
header field "x-xss-protection" = "0"
header field "x-frame-options" = "SAMEORIGIN"
header field "alt-svc" = "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000"

Frame Type	=>	PING

Frame Type	=>	DATA
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://www.google.com/">here</A>.
</BODY></HTML>
```

## TLS Module — PcapNG Mode

### Command

```bash
sudo ecapture tls -m pcap -w ecap.pcapng -i ens160
```

### Full Output

```
2024-09-15T06:54:12Z INF AppName="eCapture(旁观者)"
2024-09-15T06:54:12Z INF HomePage=https://ecapture.cc
2024-09-15T06:54:12Z INF Repository=https://github.com/gojue/ecapture
2024-09-15T06:54:12Z INF Author="CFC4N <cfc4ncs@gmail.com>"
2024-09-15T06:54:12Z INF Description="Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supported on Linux/Android kernels for amd64/arm64."
2024-09-15T06:54:12Z INF Version=linux_arm64:0.8.6-20240915-d87ae48:5.15.0-113-generic
2024-09-15T06:54:12Z INF Listen=localhost:28256
2024-09-15T06:54:12Z INF eCapture running logs logger=
2024-09-15T06:54:12Z INF the file handler that receives the captured event eventCollector=
2024-09-15T06:54:12Z WRN ========== module starting. ==========
2024-09-15T06:54:12Z INF Kernel Info=5.15.152 Pid=230440
2024-09-15T06:54:12Z INF BTF bytecode mode: CORE. btfMode=0
2024-09-15T06:54:12Z INF listen=localhost:28256
2024-09-15T06:54:12Z INF module initialization. isReload=false moduleName=EBPFProbeOPENSSL
2024-09-15T06:54:12Z INF Module.Run()
2024-09-15T06:54:12Z INF https server starting...You can update the configuration file via the HTTP interface.
2024-09-15T06:54:12Z WRN OpenSSL/BoringSSL version not found from shared library file, used default version OpenSSL Version=linux_default_3_0
2024-09-15T06:54:12Z INF HOOK type:Openssl elf ElfType=2 IFindex=2 IFname=ens160 PcapFilter= binrayPath=/usr/lib/aarch64-linux-gnu/libssl.so.3
2024-09-15T06:54:12Z INF Hook masterKey function Functions=["SSL_get_wbio","SSL_in_before","SSL_do_handshake"]
2024-09-15T06:54:12Z INF target all process.
2024-09-15T06:54:12Z INF target all users.
2024-09-15T06:54:12Z INF setupManagers eBPFProgramType=PcapNG
2024-09-15T06:54:12Z INF BPF bytecode file is matched. bpfFileName=user/bytecode/openssl_3_0_0_kern_core.o
2024-09-15T06:54:12Z INF packets saved into pcapng file. pcapng path=/home/ecapture/ecap.pcapng
2024-09-15T06:54:12Z INF perfEventReader created mapSize(MB)=4
2024-09-15T06:54:12Z INF perfEventReader created mapSize(MB)=4
2024-09-15T06:54:12Z INF module started successfully. isReload=false moduleName=EBPFProbeOPENSSL
2024-09-15T06:54:14Z INF packets saved into pcapng file. count=4
2024-09-15T06:54:16Z INF non-TLSv1.3 cipher suite found CLientRandom=f08e8d784962d1693c042f9fe266345507ccfaba58b823904a357f30dbfa1e71 CipherId=0
2024-09-15T06:54:16Z INF non-TLSv1.3 cipher suite found CLientRandom=f08e8d784962d1693c042f9fe266345507ccfaba58b823904a357f30dbfa1e71 CipherId=0
2024-09-15T06:54:16Z INF packets saved into pcapng file. count=183
2024-09-15T06:54:16Z INF CLIENT_RANDOM save success CLientRandom=f08e8d784962d1693c042f9fe266345507ccfaba58b823904a357f30dbfa1e71 TlsVersion=TLS1_2_VERSION bytes=176
2024-09-15T06:54:18Z INF packets saved into pcapng file. count=65
^C2024-09-15T06:54:18Z INF module close.
2024-09-15T06:54:18Z INF packets saved into pcapng file. count=3
2024-09-15T06:54:18Z INF packets saved into pcapng file. count=255
2024-09-15T06:54:18Z INF Module closed,message recived from Context
2024-09-15T06:54:18Z INF iModule module close
2024-09-15T06:54:18Z INF bye bye.
```

Use `Wireshark` to open the `ecap.pcapng` file to view the decrypted plaintext data packets.

## TLS Module — Keylog Mode

### Command

```bash
sudo ecapture tls -m keylog -keylogfile=openssl_keylog.log
```

The captured TLS Master Secret is saved to `openssl_keylog.log` in the standard `SSLKEYLOGFILE` format. You can use this with `tcpdump` + `Wireshark`, or directly with `tshark`:

```bash
tshark -o tls.keylog_file:ecapture_masterkey.log -Y http -T fields -e http.file_data -f "port 443" -i eth0
```

## GoTLS Module

### Command

```bash
# Terminal 1: Start eCapture targeting a Go binary
sudo ecapture gotls --elfpath=/home/cfc4n/go_https_client --hex

# Terminal 2: Run the Go program
/home/cfc4n/go_https_client
```

## Bash Module

### Command

```bash
sudo ecapture bash
```

Captures all bash command input/output on the system.

## MySQL Module

### Command

```bash
sudo ecapture mysqld
```

Captures SQL queries from mysqld 5.6/5.7/8.0 and MariaDB.

