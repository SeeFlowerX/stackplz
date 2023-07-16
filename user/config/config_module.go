package config

import (
    "fmt"
    "log"
    "os"
    "stackplz/pkg/util"
    "strconv"
    "strings"
    "unsafe"

    "github.com/cilium/ebpf"
)

type StackUprobeConfig struct {
    LibName string
    Library string
    Symbol  string
    Offset  uint64
}

func (this *StackUprobeConfig) IsEnable() bool {
    if this.Symbol == "" && this.Offset == 0 {
        return false
    }
    return true
}

func (this *StackUprobeConfig) Check() error {
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
    // SysTable               SysTableConfig
    Enable                 bool
    syscall_mask           uint32
    syscall                [MAX_COUNT]uint32
    syscall_blacklist_mask uint32
    syscall_blacklist      [MAX_COUNT]uint32
}

func NewSyscallConfig() *SyscallConfig {
    config := &SyscallConfig{}
    config.Enable = false
    return config
}

func (this *SyscallConfig) FillFilter(filter *SyscallFilter) {
    filter.syscall = this.syscall
    filter.syscall_mask = this.syscall_mask
    filter.syscall_blacklist = this.syscall_blacklist
    filter.syscall_blacklist_mask = this.syscall_blacklist_mask
}

func (this *SyscallConfig) UpdatePointArgsMap(SyscallPointArgsMap *ebpf.Map) error {
    // 取 syscall 参数配置 syscall_point_args_map
    points := GetAllWatchPoints()
    for nr_name, point := range points {
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] point to SysCallArgs failed", nr_name))
        }
        SyscallPointArgsMap.Update(unsafe.Pointer(&nr_point.NR), unsafe.Pointer(nr_point.GetConfig()), ebpf.UpdateAny)
    }
    return nil
}

func (this *SyscallConfig) SetUp(is_32bit bool) error {
    for i := 0; i < len(this.syscall); i++ {
        this.syscall[i] = MAGIC_SYSCALL
    }
    for i := 0; i < len(this.syscall); i++ {
        this.syscall_blacklist[i] = MAGIC_SYSCALL
    }
    return nil
}

func (this *SyscallConfig) SetSysCall(syscall string) error {
    this.Enable = true
    if syscall == "all" {
        return nil
    }
    items := strings.Split(syscall, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max syscall whitelist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for i, v := range items {
        point := GetWatchPointByName(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", v))
        }
        this.syscall[i] = uint32(nr_point.NR)
        this.syscall_mask |= (1 << i)
    }
    return nil
}

func (this *SyscallConfig) SetSysCallBlacklist(syscall_blacklist string) error {
    items := strings.Split(syscall_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max syscall blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for i, v := range items {
        point := GetWatchPointByName(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", v))
        }
        this.syscall_blacklist[i] = uint32(nr_point.NR)
        this.syscall_blacklist_mask |= (1 << i)
    }
    return nil
}

func (this *SyscallConfig) IsEnable() bool {
    return this.Enable
}

func (this *SyscallConfig) Check() error {

    return nil
}

func (this *SyscallConfig) Info() string {
    var watchlist []string
    for _, v := range this.syscall {
        if v == MAGIC_SYSCALL {
            continue
        }
        point := GetWatchPointByNR(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%d] watchpoint to SysCallArgs failed", v))
        }
        watchlist = append(watchlist, nr_point.Name())
    }
    return fmt.Sprintf("watch:%s", strings.Join(watchlist, ","))
}

type ModuleConfig struct {
    SConfig
    TidsBlacklistMask uint32
    TidsBlacklist     [MAX_COUNT]uint32
    PidsBlacklistMask uint32
    PidsBlacklist     [MAX_COUNT]uint32
    Name              string
    StackUprobeConf   StackUprobeConfig
    SysCallConf       SyscallConfig
    Config            string
}

func NewModuleConfig(logger *log.Logger) *ModuleConfig {
    config := &ModuleConfig{}
    config.SelfPid = uint32(os.Getpid())
    config.FilterMode = util.UNKNOWN_MODE
    // 首先把 logger 设置上
    config.SetLogger(logger)
    // 虽然会通过全局配置进程覆盖 但是还是做好在初始化时就进行默认赋值
    config.Uid = MAGIC_UID
    config.Pid = MAGIC_PID
    config.Tid = MAGIC_TID
    // fmt.Printf("uid:%d pid:%d tid:%d", config.Uid, config.Pid, config.Tid)
    return config
}

func (this *ModuleConfig) Check() error {

    return nil
}

func (this *ModuleConfig) Info() string {
    // 调用号信息
    return fmt.Sprintf("-")
}

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

func (this *ModuleConfig) GetCommonFilter() unsafe.Pointer {
    filter := CommonFilter{}
    filter.uid = this.Uid
    filter.pid = this.Pid
    filter.tid = this.Tid
    // 这些暂时硬编码
    filter.blacklist_pids = 0
    filter.blacklist_tids = 0
    filter.blacklist_comms = 0
    filter.is_32bit = 0
    if this.Debug {
        this.logger.Printf("CommonFilter{uid=%d, pid=%d, tid=%d, is_32bit=%d}", filter.uid, filter.pid, filter.tid, filter.is_32bit)
    }
    return unsafe.Pointer(&filter)
}

func (this *ModuleConfig) GetConfigMap() ConfigMap {
    config := ConfigMap{}
    config.stackplz_pid = this.SelfPid
    config.filter_mode = this.FilterMode
    if this.Debug {
        this.logger.Printf("ConfigMap{stackplz_pid=%d}", config.stackplz_pid)
    }
    return config
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

func (this *ModuleConfig) GetSyscallFilter() SyscallFilter {
    filter := SyscallFilter{}
    filter.SetArch(this.Is32Bit)
    filter.SetAfterRead(this.AfterRead)
    this.SysCallConf.FillFilter(&filter)
    return filter
}
