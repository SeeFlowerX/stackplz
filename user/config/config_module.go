package config

import (
    "fmt"
    "os"
    "stackplz/pkg/util"
    "strconv"
    "strings"
)

type UprobeConfig struct {
    LibName string
    Library string
    Symbol  string
    Offset  uint64
}

func (this *UprobeConfig) IsEnable() bool {
    fmt.Println("this.Library", this.Library)
    fmt.Println("this.Symbol", this.Symbol)
    fmt.Println("this.Offset", this.Offset)
    if this.Symbol == "" && this.Offset == 0 {
        return false
    }
    return true
}

func (this *UprobeConfig) Check() error {
    // 对每一个hook配置进行检查
    // 1. 要有完整的库路径
    // 2. 要么指定符号 要么指定偏移
    _, err := os.Stat(this.Library)
    if err != nil {
        return err
    }

    if this.Symbol == "" && this.Offset == 0 {
        return fmt.Errorf("need symbol or offset, Library:%s\n", this.Library)
    }

    if this.Symbol != "" && this.Offset > 0 {
        return fmt.Errorf("just symbol or offset, not all of them\n")
    }

    // 虽然前面不允许用户同时设置offset和symbol 但是ebpf库必须要有一个symbol 于是这里随机下就好了
    if this.Offset > 0 {
        this.Symbol = util.RandStringBytes(8)
    }
    parts := strings.Split(this.Library, "/")
    this.LibName = parts[len(parts)-1]
    return nil
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
        // uid:                this.Uid,
        // pid:                this.Pid,
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
    PidsBlacklistMask uint32
    PidsBlacklist     [MAX_COUNT]uint32
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
//         uid:                this.Uid,
//         pid:                this.Pid,
//         nr:                 uint32(this.NR),
//         tid_blacklist_mask: this.TidsBlacklistMask,
//         tid_blacklist:      this.TidsBlacklist,
//     }
//     return filter
// }

func (this *ModuleConfig) SetTidsBlacklist(tids_blacklist string) error {
    if tids_blacklist == "" {
        return nil
    }
    this.TidsBlacklistMask = 0
    items := strings.Split(tids_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max tid blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for i, v := range items {
        value, _ := strconv.ParseUint(v, 10, 32)
        this.TidsBlacklist[i] = uint32(value)
        this.TidsBlacklistMask |= (1 << i)
    }
    return nil
}

func (this *ModuleConfig) SetPidsBlacklist(pids_blacklist string) error {
    if pids_blacklist == "" {
        return nil
    }
    this.PidsBlacklistMask = 0
    items := strings.Split(pids_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max pid blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for i, v := range items {
        value, _ := strconv.ParseUint(v, 10, 32)
        this.PidsBlacklist[i] = uint32(value)
        this.PidsBlacklistMask |= (1 << i)
    }
    return nil
}

func (this *ModuleConfig) GetUprobeStackFilter() UprobeStackFilter {
    filter := UprobeStackFilter{}
    filter.uid = this.Uid
    filter.pid = this.Pid
    filter.tid = this.Tid
    filter.tids_blacklist_mask = this.TidsBlacklistMask
    filter.tids_blacklist = this.TidsBlacklist
    filter.pids_blacklist_mask = this.PidsBlacklistMask
    filter.pids_blacklist = this.PidsBlacklist
    return filter
}
