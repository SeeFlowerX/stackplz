package main

import (
	"log"
	"stackplz/cli"
	"stackplz/pkg/ebpf"

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
