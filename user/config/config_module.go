package config

import "fmt"

type ModuleConfig struct {
    SConfig
    TidsBlacklistMask uint32
    TidsBlacklist     [MAX_COUNT]uint32
    Name              string
    Library           string
    Symbol            string
    Offset            uint64
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
