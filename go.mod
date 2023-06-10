module stackplz

go 1.18

require (
	github.com/cilium/ebpf v0.10.0
	github.com/ehids/ebpfmanager v0.3.0
	github.com/shuLhan/go-bindata v4.0.0+incompatible
	github.com/spf13/cobra v1.6.0
	golang.org/x/sys v0.6.0
)

replace github.com/cilium/ebpf => ../ebpf

replace github.com/ehids/ebpfmanager => ../ebpfmanager

require (
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/florianl/go-tc v0.4.0 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/josharian/native v0.0.0-20200817173448-b6b71def0850 // indirect
	github.com/mdlayher/netlink v1.4.1 // indirect
	github.com/mdlayher/socket v0.0.0-20210307095302-262dc9984e00 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/net v0.1.0 // indirect
)
