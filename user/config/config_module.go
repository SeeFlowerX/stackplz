package config

import "fmt"

type ModuleConfig struct {
    SConfig
    UnwindStack bool
    ShowRegs    bool
    Config      string
    NR          int64
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
    return fmt.Sprintf("sysno:%d", this.NR)
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
