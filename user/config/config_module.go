package config

import (
    "errors"
    "fmt"
    "log"
    "os"
    "regexp"
    "stackplz/user/util"
    "strconv"
    "strings"
    "unsafe"

    "golang.org/x/exp/slices"
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
        arg_type = EXP_INT
    case "uint":
        arg_type = UINT32
    case "int64":
        arg_type = INT64
    case "uint64":
        arg_type = UINT64
    case "str":
        arg_type = STRING
    case "ptr":
        arg_type = POINTER
    case "buf":
        arg_type = AT(TYPE_BUFFER_T, TYPE_POINTER, uint32(unsafe.Sizeof(uint64(0))))
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
                size, err := strconv.ParseUint(size_str, 10, 32)
                if err != nil {
                    count_index, err := ParseAsReg(size_str)
                    if err != nil {
                        return arg_type, err
                    }
                    arg_type.SetCountIndex(count_index)
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
        arg_type = arg_type.NewType(TYPE_POINTER)
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
        arg_type.SetReadIndex(read_index)
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
    // fmt.Println("arg_type", arg_type.String())
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

type SyscallConfig struct {
    logger         *log.Logger
    debug          bool
    Enable         bool
    syscall_filter SyscallFilter
    SysWhitelist   []uint32
    SysBlacklist   []uint32
}

func (this *SyscallConfig) SetDebug(debug bool) {
    this.debug = debug
}
func (this *SyscallConfig) SetLogger(logger *log.Logger) {
    this.logger = logger
}

func (this *SyscallConfig) GetSyscallFilter() SyscallFilter {
    return this.syscall_filter
}

func (this *SyscallConfig) Parse_SysWhitelist(syscall string) {
    if syscall == "" {
        this.Enable = false
        return
    }
    this.Enable = true
    this.syscall_filter.SetTraceMode(TRACE_COMMON)
    if syscall == "all" {
        this.syscall_filter.SetTraceMode(TRACE_ALL)
    } else if syscall == "%file" {
        this.syscall_filter.SetTraceMode(TRACE_FILE)
    } else if syscall == "%process" {
        this.syscall_filter.SetTraceMode(TRACE_PROCESS)
    } else if syscall == "%net" {
        this.syscall_filter.SetTraceMode(TRACE_NET)
    } else if syscall == "%signal" {
        this.syscall_filter.SetTraceMode(TRACE_SIGNAL)
    } else if syscall == "%stat" {
        this.syscall_filter.SetTraceMode(TRACE_STAT)
    } else {
        items := strings.Split(syscall, ",")
        var syscall_items []string
        for _, v := range items {
            switch v {
            case "all":
                this.syscall_filter.SetTraceMode(TRACE_ALL)
            case "%attr":
                this.syscall_filter.SetTraceMode(TRACE_FILE)
                syscall_items = append(syscall_items, []string{"setxattr", "lsetxattr", "fsetxattr"}...)
                syscall_items = append(syscall_items, []string{"getxattr", "lgetxattr", "fgetxattr"}...)
                syscall_items = append(syscall_items, []string{"listxattr", "llistxattr", "flistxattr"}...)
                syscall_items = append(syscall_items, []string{"removexattr", "lremovexattr", "fremovexattr"}...)
            case "%file":
                this.syscall_filter.SetTraceMode(TRACE_FILE)
                syscall_items = append(syscall_items, []string{"openat", "openat2", "faccessat", "faccessat2", "mknodat", "mkdirat"}...)
                syscall_items = append(syscall_items, []string{"unlinkat", "symlinkat", "linkat", "renameat", "renameat2", "readlinkat"}...)
                syscall_items = append(syscall_items, []string{"chdir", "fchdir", "chroot", "fchmod", "fchmodat", "fchownat", "fchown"}...)
            case "%process":
                this.syscall_filter.SetTraceMode(TRACE_PROCESS)
                syscall_items = append(syscall_items, []string{"clone", "clone3"}...)
                syscall_items = append(syscall_items, []string{"execve", "execveat"}...)
                syscall_items = append(syscall_items, []string{"wait4", "waitid"}...)
                syscall_items = append(syscall_items, []string{"exit", "exit_group", "rt_sigqueueinfo"}...)
                syscall_items = append(syscall_items, []string{"kill", "tkill", "tgkill"}...)
                syscall_items = append(syscall_items, []string{"pidfd_send_signal", "pidfd_open", "pidfd_getfd"}...)
            case "%net":
                this.syscall_filter.SetTraceMode(TRACE_NET)
                syscall_items = append(syscall_items, "socket")
                syscall_items = append(syscall_items, "socketpair")
                syscall_items = append(syscall_items, "bind")
                syscall_items = append(syscall_items, "listen")
                syscall_items = append(syscall_items, "accept")
                syscall_items = append(syscall_items, "connect")
                syscall_items = append(syscall_items, "getsockname")
                syscall_items = append(syscall_items, "getpeername")
                syscall_items = append(syscall_items, "sendto")
                syscall_items = append(syscall_items, "recvfrom")
                syscall_items = append(syscall_items, "setsockopt")
                syscall_items = append(syscall_items, "getsockopt")
                syscall_items = append(syscall_items, "shutdown")
                syscall_items = append(syscall_items, "recvmsg")
                syscall_items = append(syscall_items, "sendmsg")
                syscall_items = append(syscall_items, "recvmmsg")
                syscall_items = append(syscall_items, "sendmmsg")
                syscall_items = append(syscall_items, "accept4")
            case "%signal":
                this.syscall_filter.SetTraceMode(TRACE_SIGNAL)
                syscall_items = append(syscall_items, "sigaltstack")
                syscall_items = append(syscall_items, "rt_sigsuspend")
                syscall_items = append(syscall_items, "rt_sigaction")
                syscall_items = append(syscall_items, "rt_sigprocmask")
                syscall_items = append(syscall_items, "rt_sigpending")
                syscall_items = append(syscall_items, "rt_sigtimedwait")
                syscall_items = append(syscall_items, "rt_sigqueueinfo")
                syscall_items = append(syscall_items, "rt_sigreturn")
                syscall_items = append(syscall_items, "rt_tgsigqueueinfo")
                syscall_items = append(syscall_items, "kill")
                syscall_items = append(syscall_items, "tkill")
                syscall_items = append(syscall_items, "tgkill")
            case "%stat":
                this.syscall_filter.SetTraceMode(TRACE_STAT)
                syscall_items = append(syscall_items, "statfs")
                syscall_items = append(syscall_items, "fstatfs")
                syscall_items = append(syscall_items, "newfstatat")
                syscall_items = append(syscall_items, "fstat")
                syscall_items = append(syscall_items, "statx")
            default:
                syscall_items = append(syscall_items, v)
            }
        }
        // 去重
        var unique_items []string
        if this.syscall_filter.GetTraceMode() != TRACE_ALL {
            for _, v := range syscall_items {
                if !slices.Contains(unique_items, v) {
                    unique_items = append(unique_items, v)
                }
            }
        }
        for _, v := range unique_items {
            point := GetWatchPointByName(v)
            nr_point, ok := (point).(*SysCallArgs)
            if !ok {
                panic(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", v))
            }
            this.SysWhitelist = append(this.SysWhitelist, uint32(nr_point.NR))
        }
        this.syscall_filter.SetWhitelistMode(len(this.SysWhitelist) > 0)
    }
}

func (this *SyscallConfig) Parse_SysBlacklist(syscall_blacklist string) {
    items := strings.Split(syscall_blacklist, ",")
    for _, v := range items {
        point := GetWatchPointByName(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", v))
        }
        this.SysBlacklist = append(this.SysBlacklist, uint32(nr_point.NR))
    }
    this.syscall_filter.SetBlacklistMode(len(this.SysBlacklist) > 0)
}

func (this *SyscallConfig) IsEnable() bool {
    return this.Enable
}

func (this *SyscallConfig) Info() string {
    var watchlist []string
    for _, v := range this.SysWhitelist {
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
    BaseConfig

    SelfPid    uint32
    FilterMode uint32

    UidWhitelist []uint32
    UidBlacklist []uint32
    PidWhitelist []uint32
    PidBlacklist []uint32
    TidWhitelist []uint32
    TidBlacklist []uint32

    TraceIsolated bool
    HideRoot      bool
    UprobeSignal  uint32
    UnwindStack   bool
    StackSize     uint32
    ShowRegs      bool
    GetOff        bool
    RegName       string
    ExternalBTF   string
    Is32Bit       bool
    Buffer        uint32
    BrkAddr       uint64
    BrkType       uint32
    Color         bool
    DumpHex       bool

    TNamesWhitelist []string
    TNamesBlacklist []string
    Name            string
    StackUprobeConf *StackUprobeConfig
    SysCallConf     *SyscallConfig
}

func NewModuleConfig() *ModuleConfig {
    config := &ModuleConfig{}
    config.SelfPid = uint32(os.Getpid())
    config.FilterMode = util.UNKNOWN_MODE
    // 虽然会通过全局配置进程覆盖 但是还是做好在初始化时就进行默认赋值
    return config
}

func (this *ModuleConfig) InitSyscallConfig() {
    config := &SyscallConfig{}
    config.Enable = false
    config.SetDebug(this.Debug)
    config.SetLogger(this.logger)
    this.SysCallConf = config
}

func (this *ModuleConfig) InitStackUprobeConfig() {
    config := &StackUprobeConfig{}
    this.StackUprobeConf = config
}

func (this *ModuleConfig) Info() string {
    // 调用号信息
    return fmt.Sprintf("-")
}

func (this *ModuleConfig) Parse_TidBlacklist(tids_blacklist string) {
    if tids_blacklist == "" {
        return
    }
    items := strings.Split(tids_blacklist, ",")
    if len(items) > MAX_COUNT {
        panic(fmt.Sprintf("max tid blacklist count is %d, provided count:%d", MAX_COUNT, len(items)))
    }
    for _, v := range items {
        value, err := strconv.ParseUint(v, 10, 32)
        if err != nil {
            panic(err)
        }
        this.TidBlacklist = append(this.TidBlacklist, uint32(value))
    }
}

func (this *ModuleConfig) Parse_PidBlacklist(pids_blacklist string) {
    if pids_blacklist == "" {
        return
    }
    items := strings.Split(pids_blacklist, ",")
    if len(items) > MAX_COUNT {
        panic(fmt.Sprintf("max pid blacklist count is %d, provided count:%d", MAX_COUNT, len(items)))
    }
    for _, v := range items {
        value, err := strconv.ParseUint(v, 10, 32)
        if err != nil {
            panic(err)
        }
        this.PidBlacklist = append(this.PidBlacklist, uint32(value))
    }
}
func (this *ModuleConfig) Parse_Idlist(list_key, id_list string) {
    if id_list == "" {
        return
    }
    items := strings.Split(id_list, ",")
    if len(items) > MAX_COUNT {
        panic(fmt.Sprintf("max %s count is %d, provided count:%d", list_key, MAX_COUNT, len(items)))
    }
    for _, v := range items {
        value, err := strconv.ParseUint(v, 10, 32)
        if err != nil {
            panic(err)
        }
        item_value := uint32(value)
        switch list_key {
        case "UidWhitelist":
            this.UidWhitelist = append(this.UidWhitelist, item_value)
        case "UidBlacklist":
            this.UidBlacklist = append(this.UidBlacklist, item_value)
        case "PidWhitelist":
            this.PidWhitelist = append(this.PidWhitelist, item_value)
        case "PidBlacklist":
            this.PidBlacklist = append(this.PidBlacklist, item_value)
        case "TidWhitelist":
            this.TidWhitelist = append(this.TidWhitelist, item_value)
        case "TidBlacklist":
            this.TidBlacklist = append(this.TidBlacklist, item_value)
        default:
            panic(fmt.Sprintf("unknown list_key:%s", list_key))
        }
    }
}

func (this *ModuleConfig) SetTNamesBlacklist(t_names_blacklist string) {
    if t_names_blacklist == "" {
        return
    }
    items := strings.Split(t_names_blacklist, ",")
    if len(items) > MAX_COUNT {
        panic(fmt.Sprintf("max thread name blacklist count is %d, provided count:%d", MAX_COUNT, len(items)))
    }
    for _, v := range items {
        this.TNamesBlacklist = append(this.TNamesBlacklist, v)
    }
}
func (this *ModuleConfig) SetTNamesWhitelist(t_names_blacklist string) {
    if t_names_blacklist == "" {
        return
    }
    items := strings.Split(t_names_blacklist, ",")
    if len(items) > MAX_COUNT {
        panic(fmt.Sprintf("max thread name whitelist count is %d, provided count:%d", MAX_COUNT, len(items)))
    }
    for _, v := range items {
        this.TNamesWhitelist = append(this.TNamesWhitelist, v)
    }
}

func (this *ModuleConfig) GetCommonFilter() CommonFilter {
    filter := CommonFilter{}
    filter.is_32bit = 0

    // 这些暂时硬编码
    for i := 0; i < MAX_COUNT; i++ {
        filter.pid_list[i] = MAGIC_PID
    }

    filter.thread_name_whitelist = 0
    if len(this.TNamesWhitelist) > 0 {
        filter.thread_name_whitelist = 1
    }
    filter.trace_uid_group = 0
    if this.TraceIsolated {
        filter.trace_uid_group = 1
    }
    filter.signal = this.UprobeSignal
    if this.Debug {
        this.logger.Printf("CommonFilter{uid=%d, pid=%d, tid=%d, is_32bit=%d, whitelist:%d}", filter.uid, filter.pid, filter.tid, filter.is_32bit, filter.thread_name_whitelist)
    }
    return filter
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
