package config

import (
    "errors"
    "fmt"
    "os"
    "regexp"
    "stackplz/user/util"
    "strconv"
    "strings"
    "unsafe"

    "github.com/cilium/ebpf"
)

type StackUprobeConfig struct {
    LibName string
    LibPath string
    Points  []UprobeArgs
}

func ParseStrAsNum(v string) (uint64, error) {
    if strings.HasPrefix(v, "0x") {
        op_value, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32)
        if err != nil {
            err = errors.New(fmt.Sprintf("parse op_value:%s as hex failed, err:%v", v, err))
            return 0, err
        }
        return op_value, nil
    } else {
        op_value, err := strconv.ParseUint(v, 10, 32)
        if err != nil {
            err = errors.New(fmt.Sprintf("parse op_value:%s failed, err:%v", v, err))
            return 0, err
        }
        return op_value, nil
    }
}

func ParseArgType(arg_str string) (ArgType, error) {
    // str
    // int:x10
    // buf:64:sp+0x20-0x8
    // 解析为单个参数的读取配置 -> 在何处读、读取类型
    var err error = nil
    var arg_type ArgType
    var to_ptr bool = false
    var arg_desc string = ""
    var arg_index string = ""
    var size_str string = ""
    items := strings.Split(arg_str, ":")
    if len(items) == 1 {
        arg_desc = items[0]
    } else if len(items) == 2 {
        arg_desc = items[0]
        arg_index = items[1]
    } else if len(items) == 3 {
        arg_desc = items[0]
        size_str = items[1]
        arg_index = items[2]
    } else {
        return arg_type, errors.New(fmt.Sprintf("parse arg_str:%s failed, err:%v", arg_str, err))
    }
    if strings.HasPrefix(arg_desc, "*") {
        to_ptr = true
        arg_desc = arg_desc[1:]
    }
    switch arg_desc {
    case "int":
        arg_type = INT
    case "str":
        arg_type = STRING
    case "ptr":
        arg_type = POINTER
    case "buf":
        arg_type = BUFFER_T
        arg_type.SetSize(256)
        // 特别处理
        if len(items) == 2 {
            size_str = arg_index
            arg_index = ""
        }
        if size_str != "" {
            if strings.HasPrefix(size_str, "0x") {
                size, err := strconv.ParseUint(strings.TrimPrefix(size_str, "0x"), 16, 32)
                if err != nil {
                    err = errors.New(fmt.Sprintf("parse size_str:%s as hex failed, arg_str:%s, err:%v", size_str, arg_str, err))
                    break
                }
                arg_type.SetSize(uint32(size))
            } else {
                size, err := strconv.ParseUint(items[1], 10, 32)
                if err != nil {
                    err = errors.New(fmt.Sprintf("parse size_str:%s as number failed, arg_str:%s, err:%v", size_str, arg_str, err))
                    break
                } else {
                    arg_type.SetSize(uint32(size))
                }
            }
        }
    case "pattr":
        arg_type = PTHREAD_ATTR
    default:
        err = errors.New(fmt.Sprintf("unsupported arg_type:%s", items[0]))
    }
    if err != nil {
        return arg_type, err
    }
    if to_ptr {
        arg_type.ToPointer()
    }
    if arg_index != "" {
        read_offset := ""
        if len(arg_index) > 2 {
            read_offset = arg_index[2:]
            arg_index = arg_index[:2]
        }
        read_index, err := ParseAsReg(arg_index)
        if err != nil {
            return arg_type, err
        }
        arg_type.SetIndex(read_index)
        if read_offset != "" {
            var offset uint64 = 0
            if strings.HasPrefix(read_offset, "+") {
                op_add_items := strings.Split(read_offset, "+")
                for _, v := range op_add_items {
                    v = strings.TrimSpace(v)
                    if v == "" {
                        continue
                    }
                    op_sub_items := strings.Split(v, "-")
                    op_value, err := ParseStrAsNum(op_sub_items[0])
                    if err != nil {
                        return arg_type, err
                    }
                    offset += op_value
                    if len(op_sub_items) > 1 {
                        for _, v2 := range op_sub_items[1:] {
                            v2 = strings.TrimSpace(v2)
                            op_value, err := ParseStrAsNum(v2)
                            if err != nil {
                                return arg_type, err
                            }
                            offset -= op_value
                        }
                    }
                }
            } else if strings.HasPrefix(read_offset, "-") {
                op_sub_items := strings.Split(read_offset, "-")
                for _, v := range op_sub_items {
                    v = strings.TrimSpace(v)
                    if v == "" {
                        continue
                    }
                    op_add_items := strings.Split(v, "+")
                    op_value, err := ParseStrAsNum(op_add_items[0])
                    if err != nil {
                        return arg_type, err
                    }
                    offset -= op_value
                    if len(op_add_items) > 1 {
                        for _, v2 := range op_add_items[1:] {
                            v2 = strings.TrimSpace(v2)
                            op_value, err := ParseStrAsNum(v2)
                            if err != nil {
                                return arg_type, err
                            }
                            offset += op_value
                        }
                    }
                }
            } else {
                return arg_type, errors.New(fmt.Sprintf("parse read_offset:%s failed", read_offset))
            }
            arg_type.SetReadOffset(uint32(offset))
        }
    }
    return arg_type, err
}

func (this *StackUprobeConfig) IsEnable() bool {
    return len(this.Points) > 0
}

func (this *StackUprobeConfig) ParseConfig(configs []string) (err error) {
    // strstr+0x0[str,str] 命中 strstr + 0x0 时将x0和x1读取为字符串
    // write[int,buf:128,int] 命中 write 时将x0读取为int、x1读取为字节数组、x2读取为int
    // 0x89ab[buf:64,int] 命中hook点时读取 x0 处64字节数据 读取 x1 值
    // 0x89ab[buf:64:sp+0x20-0x8] 命中hook点时读取 sp+0x20-0x8 处64字节数据
    // 0x89ab[buf:x1:sp+0x20-0x8] 命中hook点时读取 sp+0x20-0x8 处x1寄存器大小字节数据
    for point_index, config_str := range configs {
        reg := regexp.MustCompile(`(\w+)(\+0x[[:xdigit:]]+)?(\[.+?\])?`)
        match := reg.FindStringSubmatch(config_str)

        if len(match) > 0 {
            hook_point := UprobeArgs{}
            hook_point.Index = uint32(point_index)
            hook_point.Offset = 0x0
            hook_point.LibPath = this.LibPath
            sym_or_off := match[1]
            hook_point.PointName = sym_or_off
            if strings.HasPrefix(sym_or_off, "0x") {
                offset, err := strconv.ParseUint(strings.TrimPrefix(sym_or_off, "0x"), 16, 64)
                if err != nil {
                    return errors.New(fmt.Sprintf("parse for %s failed, sym_or_off:%s err:%v", config_str, sym_or_off, err))
                }
                hook_point.Offset = offset
                hook_point.Symbol = ""
            } else {
                hook_point.Symbol = sym_or_off
            }
            off := match[2]
            if off != "" {
                if strings.HasPrefix(off, "+0x") {
                    offset, err := strconv.ParseUint(strings.TrimPrefix(off, "+0x"), 16, 64)
                    if err != nil {
                        return errors.New(fmt.Sprintf("parse for %s failed, off:%s err:%v", config_str, off, err))
                    }
                    hook_point.Offset = offset
                }
            }
            if match[3] != "" {
                hook_point.ArgsStr = match[3][1 : len(match[3])-1]
                args := strings.Split(hook_point.ArgsStr, ",")
                for arg_index, arg_str := range args {
                    arg_name := fmt.Sprintf("arg_%d", arg_index)
                    arg := PointArg{arg_name, UPROBE_ENTER_READ, INT, "???"}
                    arg_type, err := ParseArgType(arg_str)
                    if err != nil {
                        return err
                    }
                    arg.ArgType = arg_type
                    hook_point.Args = append(hook_point.Args, arg)
                }
            }
            this.Points = append(this.Points, hook_point)
        } else {
            return errors.New(fmt.Sprintf("parse for %s failed", config_str))
        }
    }
    return nil
}

func (this *StackUprobeConfig) UpdatePointArgsMap(UprobePointArgsMap *ebpf.Map) error {
    for _, uprobe_point := range this.Points {
        err := UprobePointArgsMap.Update(unsafe.Pointer(&uprobe_point.Index), unsafe.Pointer(uprobe_point.GetConfig()), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    return nil
}

func (this *StackUprobeConfig) Check() error {
    if len(this.Points) == 0 {
        return fmt.Errorf("need hook point count is 0 :(")
    }
    _, err := os.Stat(this.LibPath)
    if err != nil {
        return err
    }
    parts := strings.Split(this.LibPath, "/")
    this.LibName = parts[len(parts)-1]
    return nil
}

type SyscallConfig struct {
    SConfig
    HookALL           bool
    Enable            bool
    syscall_whitelist []uint32
    syscall_blacklist []uint32
}

func NewSyscallConfig() *SyscallConfig {
    config := &SyscallConfig{}
    config.Enable = false
    return config
}

func (this *SyscallConfig) GetSyscallFilter() SyscallFilter {
    filter := SyscallFilter{}
    filter.SetArch(this.Is32Bit)
    filter.SetHookALL(this.HookALL)
    filter.SetWhitelistMode(len(this.syscall_whitelist) > 0)
    filter.SetBlacklistMode(len(this.syscall_blacklist) > 0)
    return filter
}

func (this *SyscallConfig) UpdateWhiteList(whitelist *ebpf.Map) error {
    for _, v := range this.syscall_whitelist {
        err := whitelist.Update(unsafe.Pointer(&v), unsafe.Pointer(&v), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    return nil
}

func (this *SyscallConfig) UpdateBlackList(blacklist *ebpf.Map) error {
    for _, v := range this.syscall_blacklist {
        err := blacklist.Update(unsafe.Pointer(&v), unsafe.Pointer(&v), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    return nil
}

func (this *SyscallConfig) UpdatePointArgsMap(SyscallPointArgsMap *ebpf.Map) error {
    // 取 syscall 参数配置 syscall_point_args_map
    points := GetAllWatchPoints()
    for nr_name, point := range points {
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] point to SysCallArgs failed", nr_name))
        }
        // 这里可以改成只更新追踪的syscall以加快速度
        err := SyscallPointArgsMap.Update(unsafe.Pointer(&nr_point.NR), unsafe.Pointer(nr_point.GetConfig()), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    if this.Debug {
        this.logger.Printf("update syscall_point_args_map success")
    }
    return nil
}

const (
    SYSCALL_GROUP_ALL uint32 = iota
    SYSCALL_GROUP_KILL
    SYSCALL_GROUP_EXIT
)

func (this *SyscallConfig) SetSysCall(syscall string) error {
    this.Enable = true
    if syscall == "all" {
        this.HookALL = true
        return nil
    }
    items := strings.Split(syscall, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max syscall whitelist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for _, v := range items {
        point := GetWatchPointByName(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            return errors.New(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", v))
        }
        this.syscall_whitelist = append(this.syscall_whitelist, uint32(nr_point.NR))
    }
    return nil
}

func (this *SyscallConfig) SetSysCallBlacklist(syscall_blacklist string) error {
    items := strings.Split(syscall_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max syscall blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for _, v := range items {
        point := GetWatchPointByName(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", v))
        }
        this.syscall_blacklist = append(this.syscall_blacklist, uint32(nr_point.NR))
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
    for _, v := range this.syscall_whitelist {
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
    TNamesWhitelist   []string
    TNamesBlacklist   []string
    Name              string
    StackUprobeConf   StackUprobeConfig
    SysCallConf       SyscallConfig
}

func NewModuleConfig() *ModuleConfig {
    config := &ModuleConfig{}
    config.SelfPid = uint32(os.Getpid())
    config.FilterMode = util.UNKNOWN_MODE
    // 首先把 logger 设置上
    // config.SetLogger(logger)
    // 虽然会通过全局配置进程覆盖 但是还是做好在初始化时就进行默认赋值
    config.Uid = MAGIC_UID
    config.Pid = MAGIC_PID
    config.Tid = MAGIC_TID
    for i := 0; i < len(config.PidsBlacklist); i++ {
        config.PidsBlacklist[i] = MAGIC_PID
    }
    for i := 0; i < len(config.TidsBlacklist); i++ {
        config.PidsBlacklist[i] = MAGIC_TID
    }
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
func (this *ModuleConfig) SetTNamesBlacklist(t_names_blacklist string) error {
    if t_names_blacklist == "" {
        return nil
    }
    items := strings.Split(t_names_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max thread name blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for _, v := range items {
        this.TNamesBlacklist = append(this.TNamesBlacklist, v)
    }
    return nil
}
func (this *ModuleConfig) SetTNamesWhitelist(t_names_blacklist string) error {
    if t_names_blacklist == "" {
        return nil
    }
    items := strings.Split(t_names_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max thread name whitelist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for _, v := range items {
        this.TNamesWhitelist = append(this.TNamesWhitelist, v)
    }
    return nil
}

func (this *ModuleConfig) UpdateRevFilter(rev_filter *ebpf.Map) (err error) {
    // ./stackplz -n com.starbucks.cn --iso -s newfstatat,openat,faccessat --hide-root -o tmp.log -q
    var rev_list []string = []string{
        "/sbin/su",
        "/sbin/.magisk/",
        "/dev/.magisk",
        "/system/bin/magisk",
        "/system/bin/su",
        "/system/xbin/su",
        // "ro.debuggable",
        "/proc/mounts",
        "which su",
        "mount",
    }

    for _, v := range rev_list {
        if len(v) > 32 {
            panic(fmt.Sprintf("[%s] rev string max len is 32", v))
        }
        key_value := 1
        filter := RevFilter{}
        copy(filter.RevString[:], v)
        err = rev_filter.Update(unsafe.Pointer(&filter), unsafe.Pointer(&key_value), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    return err
}

func (this *ModuleConfig) UpdateThreadFilter(thread_filter *ebpf.Map) (err error) {
    var thread_blacklist []string = []string{
        "RenderThread",
        "FinalizerDaemon",
        "RxCachedThreadS",
        "mali-cmar-backe",
        "mali-utility-wo",
        "mali-mem-purge",
        "mali-hist-dump",
        "hwuiTask0",
        "hwuiTask1",
        "NDK MediaCodec_",
    }

    for _, v := range thread_blacklist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        thread_value := 1
        filter := ThreadFilter{}
        copy(filter.ThreadName[:], v)
        err = thread_filter.Update(unsafe.Pointer(&filter), unsafe.Pointer(&thread_value), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    for _, v := range this.TNamesBlacklist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        thread_value := 1
        filter := ThreadFilter{}
        copy(filter.ThreadName[:], v)
        err = thread_filter.Update(unsafe.Pointer(&filter), unsafe.Pointer(&thread_value), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    for _, v := range this.TNamesWhitelist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        thread_value := 2
        filter := ThreadFilter{}
        copy(filter.ThreadName[:], v)
        err = thread_filter.Update(unsafe.Pointer(&filter), unsafe.Pointer(&thread_value), ebpf.UpdateAny)
        if err != nil {
            return err
        }
    }
    return err
}
func (this *ModuleConfig) GetCommonFilter() unsafe.Pointer {
    filter := CommonFilter{}
    filter.is_32bit = 0
    filter.uid = this.Uid
    filter.pid = this.Pid
    filter.tid = this.Tid
    // 这些暂时硬编码
    for i := 0; i < MAX_COUNT; i++ {
        filter.pid_list[i] = MAGIC_PID
    }
    for i := 0; i < MAX_COUNT; i++ {
        filter.blacklist_pids[i] = this.PidsBlacklist[i]
    }
    for i := 0; i < MAX_COUNT; i++ {
        filter.blacklist_tids[i] = this.TidsBlacklist[i]
    }
    filter.thread_name_whitelist = 0
    if len(this.TNamesWhitelist) > 0 {
        filter.thread_name_whitelist = 1
    }
    filter.trace_isolated = 0
    if this.TraceIsolated {
        filter.trace_isolated = 1
    }
    filter.signal = this.UprobeSignal
    if this.Debug {
        this.logger.Printf("CommonFilter{uid=%d, pid=%d, tid=%d, is_32bit=%d, whitelist:%d}", filter.uid, filter.pid, filter.tid, filter.is_32bit, filter.thread_name_whitelist)
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
