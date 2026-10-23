module github.com/gojue/ecapture/v2

go 1.26.0

require (
	github.com/cilium/ebpf v0.22.0
	github.com/gojue/ebpfmanager v0.6.0
	github.com/google/gopacket v1.1.19
	github.com/jschwinger233/elibpcap v1.1.0
	github.com/rs/zerolog v1.35.1
	github.com/shuLhan/go-bindata v4.0.0+incompatible
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.12.1
	github.com/ulikunitz/xz v0.5.17
	golang.org/x/arch v0.32.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/cloudflare/cbpfc v0.0.0-20260901110337-083e74b275b0 // indirect
	github.com/florianl/go-tc v0.4.8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.2.0 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.8.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/google/gopacket v1.1.19 => github.com/cfc4n/gopacket v1.1.20
