package config

import "fmt"

type UprobeConfig struct {
    Library string
    Symbol  string
    Offset  uint64
}

func (this *UprobeConfig) IsEnable() bool {
    if this.Symbol == "" && this.Offset == 0 {
        return false
    }
    return true
}

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

func (this *SyscallConfig) IsEnable() bool {
    if this.NR == 0 {
        return false
    }
    return true
}

func (this *SyscallConfig) Check() error {

    return nil
}

func (this *SyscallConfig) Info() string {
    // 调用号信息
    return fmt.Sprintf("sysno:%d", this.NR)
}

func (this *SyscallConfig) GetFilter() SyscallFilter {
    filter := SyscallFilter{
        // uid:                uint32(this.Uid),
        // pid:                uint32(this.Pid),
        // nr:                 uint32(this.NR),
        // tid_blacklist_mask: this.TidsBlacklistMask,
        // tid_blacklist:      this.TidsBlacklist,
    }
    return filter
}

type ModuleConfig struct {
    SConfig
    TidsBlacklistMask uint32
    TidsBlacklist     [MAX_COUNT]uint32
    Name              string
    UprobeConf        UprobeConfig
    SyscallConf       SyscallConfig
    SysCall           string
    Config            string
}

func NewModuleConfig() *ModuleConfig {
    config := &ModuleConfig{}
    return config
}

func (this *ModuleConfig) Check() error {

    return nil
}

func (this *ModuleConfig) Info() string {
    // 调用号信息
    return fmt.Sprintf("sysno:%s", this.SysCall)
}

// func (this *ModuleConfig) GetFilter() ModuleFilter {
//     filter := ModuleFilter{
//         uid:                uint32(this.Uid),
//         pid:                uint32(this.Pid),
//         nr:                 uint32(this.NR),
//         tid_blacklist_mask: this.TidsBlacklistMask,
//         tid_blacklist:      this.TidsBlacklist,
//     }
//     return filter
// }
