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
    arg_filter *[]ArgFilter
    LibName    string
    LibPath    string
    Points     []UprobeArgs
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

func (this *StackUprobeConfig) ParseArgType(arg_str string) (ArgType, error) {
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
    arg_desc_items := strings.SplitN(arg_desc, ".", 2)
    var index_items []uint32
    if len(arg_desc_items) == 2 {
        arg_desc = arg_desc_items[0]
        filter_names := strings.Split(arg_desc_items[1], ".")
        for _, filter_name := range filter_names {
            for _, arg_filter := range *this.arg_filter {
                if arg_filter.Match(filter_name) {
                    index_items = append(index_items, arg_filter.Filter_index)
                }
            }
        }
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
        for i := 0; i < MAX_FILTER_COUNT; i++ {
            if i < len(index_items) {
                arg_type.FilterIdx[i] = index_items[i]
            }
        }
    case "ptr":
        arg_type = POINTER
    case "buf":
        arg_type = AT(TYPE_BUFFER_T, TYPE_POINTER, uint32(unsafe.Sizeof(uint64(0))))
        arg_type.SetReadCount(256)
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
                arg_type.SetReadCount(uint32(size))
            } else {
                size, err := strconv.ParseUint(size_str, 10, 32)
                if err != nil {
                    count_index, err := ParseAsReg(size_str)
                    if err != nil {
                        return arg_type, err
                    }
                    arg_type.SetCountIndex(count_index)
                } else {
                    arg_type.SetReadCount(uint32(size))
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
        arg_type = arg_type.NewBaseType(TYPE_POINTER)
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

func (this *StackUprobeConfig) SetArgFilterRule(arg_filter *[]ArgFilter) {
    this.arg_filter = arg_filter
}

func (this *StackUprobeConfig) Parse_HookPoint(configs []string) (err error) {
    if this.LibPath == "" {
        return errors.New("library is empty, plz set with -l/--lib")
    }
    if len(configs) > 6 {
        return errors.New("max uprobe hook point count is 6")
    }

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
                    arg_type, err := this.ParseArgType(arg_str)
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

type PointFilter struct {
    FilterIndexList []uint32
}

type SyscallConfig struct {
    logger           *log.Logger
    debug            bool
    arg_filter       *[]ArgFilter
    Enable           bool
    TraceMode        uint32
    SyscallPointArgs []*SyscallPointArgs_T
    SysWhitelist     []uint32
    SysBlacklist     []uint32
}

func (this *SyscallConfig) SetDebug(debug bool) {
    this.debug = debug
}

func (this *SyscallConfig) SetLogger(logger *log.Logger) {
    this.logger = logger
}

func (this *SyscallConfig) SetArgFilterRule(arg_filter *[]ArgFilter) {
    this.arg_filter = arg_filter
}

func (this *SyscallConfig) Parse_SysWhitelist(text string) {
    if text == "" {
        this.Enable = false
        return
    }
    this.Enable = true
    this.TraceMode = TRACE_COMMON
    items := strings.Split(text, ",")
    var syscall_items []string
    for _, v := range items {
        switch v {
        case "all":
            this.TraceMode = TRACE_ALL
            syscall_items = []string{}
            break
        case "%attr":
            syscall_items = append(syscall_items, []string{"setxattr", "lsetxattr", "fsetxattr"}...)
            syscall_items = append(syscall_items, []string{"getxattr", "lgetxattr", "fgetxattr"}...)
            syscall_items = append(syscall_items, []string{"listxattr", "llistxattr", "flistxattr"}...)
            syscall_items = append(syscall_items, []string{"removexattr", "lremovexattr", "fremovexattr"}...)
        case "%file":
            syscall_items = append(syscall_items, []string{"openat", "openat2", "faccessat", "faccessat2", "mknodat", "mkdirat"}...)
            syscall_items = append(syscall_items, []string{"unlinkat", "symlinkat", "linkat", "renameat", "renameat2", "readlinkat"}...)
            syscall_items = append(syscall_items, []string{"chdir", "fchdir", "chroot", "fchmod", "fchmodat", "fchownat", "fchown"}...)
        case "%clone":
            syscall_items = append(syscall_items, []string{"clone", "clone3"}...)
        case "%exec":
            syscall_items = append(syscall_items, []string{"execve", "execveat"}...)
        case "%process":
            syscall_items = append(syscall_items, []string{"clone", "clone3"}...)
            syscall_items = append(syscall_items, []string{"execve", "execveat"}...)
            syscall_items = append(syscall_items, []string{"wait4", "waitid"}...)
            syscall_items = append(syscall_items, []string{"exit", "exit_group", "rt_sigqueueinfo"}...)
            syscall_items = append(syscall_items, []string{"pidfd_send_signal", "pidfd_open", "pidfd_getfd"}...)
        case "%net":
            syscall_items = append(syscall_items, []string{"socket", "socketpair"}...)
            syscall_items = append(syscall_items, []string{"bind", "listen", "accept", "connect"}...)
            syscall_items = append(syscall_items, []string{"getsockname", "getpeername", "setsockopt", "getsockopt"}...)
            syscall_items = append(syscall_items, []string{"sendto", "recvfrom", "sendmsg", "recvmsg"}...)
            syscall_items = append(syscall_items, []string{"shutdown", "recvmmsg", "sendmmsg", "accept4"}...)
        case "%signal":
            syscall_items = append(syscall_items, []string{"sigaltstack"}...)
            syscall_items = append(syscall_items, []string{"rt_sigsuspend", "rt_sigaction", "rt_sigprocmask", "rt_sigpending"}...)
            syscall_items = append(syscall_items, []string{"rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigreturn", "rt_tgsigqueueinfo"}...)
        case "%kill":
            syscall_items = append(syscall_items, []string{"kill", "tkill", "tgkill"}...)
        case "%stat":
            syscall_items = append(syscall_items, []string{"statfs", "fstatfs", "newfstatat", "fstat", "statx"}...)
        default:
            syscall_items = append(syscall_items, v)
        }
    }
    // 去重
    var unique_items []string
    if this.TraceMode != TRACE_ALL {
        for _, v := range syscall_items {
            if !slices.Contains(unique_items, v) {
                unique_items = append(unique_items, v)
            }
        }
    }
    for _, v := range unique_items {
        var index_items []uint32
        syscall_name := v
        items := strings.SplitN(syscall_name, ":", 2)
        if len(items) == 2 {
            syscall_name = items[0]
            filter_names := strings.Split(items[1], ".")
            // 改成map好点
            for _, filter_name := range filter_names {
                for _, arg_filter := range *this.arg_filter {
                    if arg_filter.Match(filter_name) {
                        index_items = append(index_items, arg_filter.Filter_index)
                    }
                }
            }
        }
        point := GetWatchPointByName(syscall_name)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", syscall_name))
        }
        point_args := nr_point.GetConfig()
        for i := 0; i < len(point_args.ArgTypes); i++ {
            t := &point_args.ArgTypes[i]
            if t.ArgType == STRING {
                for j := 0; j < MAX_FILTER_COUNT; j++ {
                    if j < len(index_items) {
                        t.FilterIdx[j] = index_items[j]
                    }
                }
            }
        }
        this.SyscallPointArgs = append(this.SyscallPointArgs, point_args)
        this.SysWhitelist = append(this.SysWhitelist, uint32(nr_point.NR))
    }
}

func (this *SyscallConfig) Parse_SysBlacklist(text string) {
    if text == "" {
        return
    }
    items := strings.Split(text, ",")
    for _, v := range items {
        point := GetWatchPointByName(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%s] watchpoint to SysCallArgs failed", v))
        }
        this.SysBlacklist = append(this.SysBlacklist, uint32(nr_point.NR))
    }
}

func (this *SyscallConfig) IsEnable() bool {
    return this.Enable
}

func (this *SyscallConfig) Info() string {
    var whitelist []string
    for _, v := range this.SysWhitelist {
        point := GetWatchPointByNR(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%d] watchpoint to SysCallArgs failed", v))
        }
        whitelist = append(whitelist, nr_point.Name())
    }
    var blacklist []string
    for _, v := range this.SysBlacklist {
        point := GetWatchPointByNR(v)
        nr_point, ok := (point).(*SysCallArgs)
        if !ok {
            panic(fmt.Sprintf("cast [%d] watchpoint to SysCallArgs failed", v))
        }
        blacklist = append(blacklist, nr_point.Name())
    }
    return fmt.Sprintf("whitelist:[%s];blacklist:[%s]", strings.Join(whitelist, ","), strings.Join(blacklist, ","))
}

type ModuleConfig struct {
    BaseConfig

    SelfPid     uint32
    PkgNamelist []string

    UidWhitelist   []uint32
    UidBlacklist   []uint32
    PidWhitelist   []uint32
    PidBlacklist   []uint32
    TidWhitelist   []uint32
    TidBlacklist   []uint32
    TNameWhitelist []string
    TNameBlacklist []string

    ArgFilterRule []ArgFilter

    TraceGroup   uint32
    UprobeSignal uint32
    UnwindStack  bool
    ManualStack  bool
    StackSize    uint32
    ShowRegs     bool
    GetOff       bool
    RegName      string
    ExternalBTF  string
    Is32Bit      bool
    Buffer       uint32
    BrkAddr      uint64
    BrkType      uint32
    BrkKernel    bool
    Color        bool
    DumpHex      bool
    ShowUid      bool

    Name            string
    StackUprobeConf *StackUprobeConfig
    SysCallConf     *SyscallConfig
}

func NewModuleConfig() *ModuleConfig {
    config := &ModuleConfig{}
    config.SelfPid = uint32(os.Getpid())
    config.TraceGroup = util.GROUP_NONE
    // 虽然会通过全局配置进程覆盖 但是还是做好在初始化时就进行默认赋值
    return config
}

func (this *ModuleConfig) InitSyscallConfig() {
    config := &SyscallConfig{}
    config.Enable = false
    config.SetDebug(this.Debug)
    config.SetLogger(this.logger)
    config.SetArgFilterRule(&this.ArgFilterRule)
    this.SysCallConf = config
}

func (this *ModuleConfig) InitStackUprobeConfig() {
    config := &StackUprobeConfig{}
    config.SetArgFilterRule(&this.ArgFilterRule)
    this.StackUprobeConf = config
}

func (this *ModuleConfig) Info() string {
    // 调用号信息
    return fmt.Sprintf("-")
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

func (this *ModuleConfig) Parse_Namelist(list_key, name_list string) {
    if name_list == "" {
        return
    }
    items := strings.Split(name_list, ",")
    if len(items) > MAX_COUNT {
        panic(fmt.Sprintf("max %s count is %d, provided count:%d", list_key, MAX_COUNT, len(items)))
    }
    for _, v := range items {
        switch list_key {
        case "TNameWhitelist":
            this.TNameWhitelist = append(this.TNameWhitelist, v)
        case "TNameBlacklist":
            this.TNameBlacklist = append(this.TNameBlacklist, v)
        default:
            panic(fmt.Sprintf("unknown list_key:%s", list_key))
        }
    }
}

func (this *ModuleConfig) Parse_ArgFilter(arg_filter []string) {
    for filter_index, filter_str := range arg_filter {
        var arg_filter ArgFilter
        // Filter_index 默认 0
        // 这里 +1 的原因是：很多涉及 arg_type 操作的时候可能忘了挨个复制filter_idx
        arg_filter.Filter_index = uint32(filter_index) + 1
        items := strings.SplitN(filter_str, ":", 2)
        if len(items) != 2 {
            panic(fmt.Sprintf("parse ArgFilterRule failed, filter_str:%s", filter_str))
        }
        switch items[0] {
        case "eq", "equal":
            arg_filter.Filter_type = EQUAL_FILTER
            arg_filter.Num_val = util.StrToNum64(items[1])
        case "gt", "greater":
            arg_filter.Filter_type = GREATER_FILTER
            arg_filter.Num_val = util.StrToNum64(items[1])
        case "lt", "less":
            arg_filter.Filter_type = LESS_FILTER
            arg_filter.Num_val = util.StrToNum64(items[1])
        case "w", "white":
            arg_filter.Filter_type = WHITELIST_FILTER
            str_old := []byte(items[1])
            if len(str_old) > 256 {
                panic(fmt.Sprintf("string is to long, max length is 256"))
            }
            arg_filter.OldStr_len = uint32(len(str_old))
            copy(arg_filter.OldStr_val[:], str_old)
        case "b", "black":
            arg_filter.Filter_type = BLACKLIST_FILTER
            str_old := []byte(items[1])
            if len(str_old) > 256 {
                panic(fmt.Sprintf("string is to long, max length is 256"))
            }
            arg_filter.OldStr_len = uint32(len(str_old))
            copy(arg_filter.OldStr_val[:], str_old)
        case "r", "replace":
            r_items := strings.SplitN(items[1], ":::", 2)
            if len(r_items) != 2 {
                panic(fmt.Sprintf("parse replace ArgFilterRule failed, filter_str:%s", filter_str))
            }
            arg_filter.Filter_type = REPLACE_FILTER
            str_old := []byte(r_items[0])
            str_new := []byte(r_items[1])
            str_new = append(str_new, byte(0))
            if len(str_old) > 256 || len(str_new) > 256 {
                panic(fmt.Sprintf("string is to long, max length is 256"))
            }
            arg_filter.OldStr_len = uint32(len(str_old))
            copy(arg_filter.OldStr_val[:], str_old)
            // 注意这里长度 +1 是为了能写入一个 \0
            // 由于写用户态的函数必须提前指定长度 所以这里 NewStr_len 没有其作用
            arg_filter.NewStr_len = uint32(len(str_new) + 1)
            copy(arg_filter.NewStr_val[:], str_new)
        default:
            panic(fmt.Sprintf("parse ArgFilterRule failed, filter_str:%s", filter_str))
        }
        this.ArgFilterRule = append(this.ArgFilterRule, arg_filter)
    }
}

func (this *ModuleConfig) GetCommonFilter() CommonFilter {
    filter := CommonFilter{}
    if this.Is32Bit {
        filter.is_32bit = 1
    } else {
        filter.is_32bit = 0
    }
    // 按设计应当分离 但是为了减少一个 map ...
    filter.trace_mode = this.SysCallConf.TraceMode

    filter.trace_uid_group = this.TraceGroup
    filter.signal = this.UprobeSignal
    return filter
}

func (this *ModuleConfig) GetConfigMap() ConfigMap {
    config := ConfigMap{}
    config.stackplz_pid = this.SelfPid
    if len(this.TNameWhitelist) > 0 {
        config.thread_whitelist = 1
    }
    if this.Debug {
        this.logger.Printf("ConfigMap{stackplz_pid=%d}", config.stackplz_pid)
    }
    return config
}
