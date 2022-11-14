package config

import "fmt"

type SyscallConfig struct {
    SConfig
    UnwindStack bool
    ShowRegs    bool
    Config      string
    NR          int64
}

func NewSyscallConfig() *SyscallConfig {
    config := &SyscallConfig{}
    return config
}

func (this *SyscallConfig) Check() error {

    return nil
}

func (this *SyscallConfig) Info() string {
    // 调用号信息
    return fmt.Sprintf("sysno:%d", this.NR)
}
