package config

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "stackplz/assets"
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
    UnwindStack            bool
    ShowRegs               bool
    Config                 string
    SysTable               SysTableConfig
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

func (this *SyscallConfig) UpdateArgMaskMap(argMaskMap *ebpf.Map) error {
    // 更新用于获取字符串信息的map
    for nr, table_config := range this.SysTable {
        nr_key, _ := strconv.ParseUint(nr, 10, 32)
        argMaskMap.Update(unsafe.Pointer(&nr_key), unsafe.Pointer(&table_config.Mask), ebpf.UpdateAny)
    }
    return nil
}

func (this *SyscallConfig) UpdateArgRetMaskMap(argRetMaskMap *ebpf.Map) error {
    // 和上面一样 只是也许会跟随配置文件形式发生变化 所以写了两份
    for nr, table_config := range this.SysTable {
        nr_key, _ := strconv.ParseUint(nr, 10, 32)
        argRetMaskMap.Update(unsafe.Pointer(&nr_key), unsafe.Pointer(&table_config.RetMask), ebpf.UpdateAny)
    }
    return nil
}

func (this *SyscallConfig) SetUp(is_32bit bool) error {
    var table_path string
    if is_32bit {
        table_path = "user/config/table32.json"
    } else {
        table_path = "user/config/table64.json"
    }
    this.SysTable = NewSysTableConfig()
    // 获取syscall读取参数的mask配置
    table_buffer, err := assets.Asset(table_path)
    if err != nil {
        return err
    }
    var tmp_config map[string][]interface{}
    json.Unmarshal(table_buffer, &tmp_config)
    for nr, config_arr := range tmp_config {
        table_config := TableConfig{
            Count:   uint32(config_arr[0].(float64)),
            Name:    config_arr[1].(string),
            Mask:    uint32(config_arr[2].(float64)),
            RetMask: uint32(config_arr[3].(float64)),
        }
        this.SysTable[nr] = table_config
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
        nr, err := this.SysTable.GetNR(v)
        if err != nil {
            return err
        }
        this.syscall[i] = uint32(nr)
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
        nr, err := this.SysTable.GetNR(v)
        if err != nil {
            return err
        }
        this.syscall_blacklist[i] = uint32(nr)
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
    // 调用号信息
    var name_lsit []string
    for _, v := range this.syscall {
        if v == 0 {
            continue
        }
        name_lsit = append(name_lsit, this.SysTable.GetName(v))
    }
    return fmt.Sprintf("nr(s):%s", strings.Join(name_lsit[:], ","))
}

// func (this *SyscallConfig) GetFilter() SyscallFilter {
//     filter := SyscallFilter{
//         // uid:                this.Uid,
//         // pid:                this.Pid,
//         // nr:                 uint32(this.NR),
//         // tid_blacklist_mask: this.TidsBlacklistMask,
//         // tid_blacklist:      this.TidsBlacklist,
//     }
//     return filter
// }

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
    // 暂时硬编码为 false
    filter.is_32bit = 0
    if this.Debug {
        this.logger.Printf("CommonFilter{uid=%d, pid=%d, tid=%d, is_32bit=%d}", filter.uid, filter.pid, filter.tid, filter.is_32bit)
    }
    return unsafe.Pointer(&filter)
}

func (this *ModuleConfig) GetConfigMap() ConfigMap {
    config := ConfigMap{}
    config.stackplz_pid = this.SelfPid
    if this.Debug {
        this.logger.Printf("ConfigMap{stackplz_pid=%d}", config.stackplz_pid)
    }
    return config
}

func (this *ModuleConfig) GetVmaInfoFilter() unsafe.Pointer {
    filter := VmaInfoFilter{}
    filter.uid = this.Uid
    filter.pid = this.Pid
    return unsafe.Pointer(&filter)
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
    filter.uid = this.Uid
    filter.pid = this.Pid
    filter.tid = this.Tid
    filter.tids_blacklist_mask = this.TidsBlacklistMask
    filter.tids_blacklist = this.TidsBlacklist
    filter.pids_blacklist_mask = this.PidsBlacklistMask
    filter.pids_blacklist = this.PidsBlacklist
    filter.SetArch(this.Is32Bit)
    filter.SetAfterRead(this.AfterRead)
    this.SysCallConf.FillFilter(&filter)
    return filter
}
