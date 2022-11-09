package main

import (
    "edemo/cli"
    "edemo/pkg/ebpf"
    "log"

    _ "github.com/shuLhan/go-bindata" // add for bindata in Makefile
)

func main() {
    enable, e := ebpf.IsEnableBPF()
    if e != nil {
        log.Fatalf("Kernel config read failed, error:%v", e)
    }

    if !enable {
        log.Fatalf("Kernel not support, error:%v", e)
    }

    cli.Start()
}
