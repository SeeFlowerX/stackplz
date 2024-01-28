package config

import (
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "regexp"
    "stackplz/user/argtype"
    . "stackplz/user/common"
    "stackplz/user/util"
    "strconv"
    "strings"
    "sync"

    "github.com/cilium/ebpf/perf"
    "golang.org/x/exp/slices"
)

type StackUprobeConfig struct {
    arg_filter   *[]ArgFilter
    LibName      string
    LibPath      string
    RealFilePath string
    NonElfOffset uint64
    Points       []*UprobeArgs
    DumpHex      bool
    Color        bool
}

func ParseStrAsNum(v string) (uint64, error) {
    op_value, err := strconv.ParseUint(v, 0, 32)
    if err != nil {
        err = errors.New(fmt.Sprintf("parse op_value:%s failed, err:%v", v, err))
        return 0, err
    }
    return op_value, nil
}

func (this *StackUprobeConfig) ParseArgType(arg_str string, point_arg *PointArg) error {
    // ./stackplz -n icu.nullptr.nativetest -l libc.so -w 0x5B950[*int:x20,*int:x20+4] -w 0x5B7BC[*int:x20,*int:x20+4]
    // ./stackplz -n com.xingin.xhs -l libart.so -w 0x4B8A74[str:x22,str:x8] --tname com.xingin.xhs --reg x28
    // str
    // int:x10
    // buf:64:sp+0x20-0x8
    // 解析为单个参数的读取配置 -> 在何处读、读取类型
    var err error = nil
    var to_ptr bool = false
    var type_name string = ""
    var read_op_str string = ""
    var arg_filter string = ""
    var items []string
    // 参数是否为指针
    if strings.HasPrefix(arg_str, "*") {
        to_ptr = true
        type_name = arg_str[1:]
        items = strings.SplitN(arg_str[1:], ":", 2)
    } else {
        items = strings.SplitN(arg_str, ":", 2)
    }
    // 提取类型、参数读取索引
    if len(items) == 1 {
        type_name = items[0]
    } else if len(items) == 2 {
        type_name = items[0]
        read_op_str = items[1]
    } else {
        return errors.New(fmt.Sprintf("parse arg_str:%s failed, err:%v", arg_str, err))
    }
    // 提取参数过滤规则
    filter_items := strings.SplitN(type_name, ".", 2)
    if len(filter_items) == 2 {
        type_name = filter_items[0]
        arg_filter = filter_items[1]
    }
    to_hex := false
    if strings.HasSuffix(type_name, "x") {
        to_hex = true
        type_name = type_name[:len(type_name)-1]
    }
    switch type_name {
    case "int":
        point_arg.SetTypeIndex(INT)
    case "uint":
        point_arg.SetTypeIndex(UINT)
    case "int8":
        point_arg.SetTypeIndex(INT8)
    case "uint8":
        point_arg.SetTypeIndex(UINT8)
    case "int16":
        point_arg.SetTypeIndex(INT16)
    case "uint16":
        point_arg.SetTypeIndex(UINT16)
    case "int32":
        point_arg.SetTypeIndex(INT32)
    case "uint32":
        point_arg.SetTypeIndex(UINT32)
    case "int64":
        point_arg.SetTypeIndex(INT64)
    case "uint64":
        point_arg.SetTypeIndex(UINT64)
    case "str", "std":
        // std 特指 std::string
        if type_name == "str" {
            point_arg.SetTypeIndex(STRING)
        } else {
            point_arg.SetTypeIndex(STD_STRING)
        }
        filter_names := strings.Split(arg_filter, ".")
        for _, filter_name := range filter_names {
            for _, arg_filter := range *this.arg_filter {
                if arg_filter.Match(filter_name) {
                    point_arg.AddFilterIndex(arg_filter.Filter_index)
                }
            }
        }
        point_arg.SetGroupType(EBPF_UPROBE_ENTER)
    case "ptr":
        point_arg.SetTypeIndex(POINTER)
        filter_names := strings.Split(arg_filter, ".")
        for _, filter_name := range filter_names {
            for _, arg_filter := range *this.arg_filter {
                if arg_filter.Match(filter_name) {
                    point_arg.AddFilterIndex(arg_filter.Filter_index)
                }
            }
        }
    case "ptr_arr", "uint_arr", "int_arr":
        arr_items := strings.SplitN(read_op_str, ":", 2)
        var count_str = ""
        if len(arr_items) == 1 {
            count_str = arr_items[0]
            read_op_str = ""
        } else if len(arr_items) == 2 {
            count_str = arr_items[0]
            read_op_str = arr_items[1]
        } else {
            return errors.New(fmt.Sprintf("parse %s arg_str:%s failed", type_name, arg_str))
        }
        size, err := strconv.ParseUint(count_str, 0, 32)
        if err != nil {
            return errors.New(fmt.Sprintf("parse %s arg_str:%s failed", type_name, arg_str))
        }
        var at argtype.IArgType
        if type_name == "int_arr" {
            at = argtype.R_NUM_ARRAY(INT, uint32(size))
        } else if type_name == "uint_arr" {
            at = argtype.R_NUM_ARRAY(UINT, uint32(size))
        } else {
            at = argtype.R_NUM_ARRAY(UINT64, uint32(size))
        }
        point_arg.SetTypeIndex(at.GetTypeIndex())
        point_arg.SetGroupType(EBPF_UPROBE_ENTER)
    case "buf":
        // 对于 buf 类型 其参数读取索引位于最后
        // 0x89ab[buf:64,int] 命中hook点时读取 x0 处64字节数据 读取 x1 值
        // 0x89ab[buf:64:sp+0x20-0x8] 命中hook点时读取 sp+0x20-0x8 处64字节数据
        // 0x89ab[buf:x1:sp+0x20-0x8] 命中hook点时读取 sp+0x20-0x8 处x1寄存器大小字节数据
        // 命令行读取的时候默认读取大小为 256 可以指定为比这个更大的数 但是不能超过 4096
        at := argtype.R_BUFFER_LEN(256)
        buf_items := strings.SplitN(read_op_str, ":", 2)
        var size_str = ""
        if len(buf_items) == 1 {
            size_str = buf_items[0]
            read_op_str = ""
        } else if len(buf_items) == 2 {
            size_str = buf_items[0]
            read_op_str = buf_items[1]
        } else {
            return errors.New(fmt.Sprintf("parse buf arg_str:%s failed", arg_str))
        }
        if size_str != "" {
            // base 指定为 0 的时候 会自动判断是不是16进制 但必须有 0x/0X 前缀
            size, err := strconv.ParseUint(size_str, 0, 32)
            if err == nil {
                // 以指定长度作为读取大小
                at = argtype.R_BUFFER_LEN(uint32(size))
            } else {
                // 以寄存器的值作为读取大小
                at = argtype.R_BUFFER_REG(GetRegIndex(size_str))
            }
        }
        at.SetDumpHex(this.DumpHex)
        at.SetColor(this.Color)
        point_arg.SetTypeIndex(at.GetTypeIndex())
        // 这个设定用于指示是否进一步读取和解析
        point_arg.SetGroupType(EBPF_UPROBE_ENTER)
    default:
        err = errors.New(fmt.Sprintf("unsupported type:%s", items[0]))
    }
    if err != nil {
        return err
    }
    if to_hex {
        point_arg.SetHexFormat()
    }
    if to_ptr {
        point_arg.ToPointerType()
        point_arg.SetGroupType(EBPF_UPROBE_ENTER)
    }

    // ./stackplz -n com.termux -l libtest.so -w 0x16254[buf:64:sp+0x20-0x8.+8.-4+0x16]
    // read_op_str -> "sp+0x20-0x8.+8.-4+0x16"
    // 该命令含义为
    // 1. 在 libtest.so 偏移 0x16254 处hook
    // 2. 计算 sp+0x20-0x8 后读取指针
    // 3. 在上一步结果上 +8 后读取指针
    // 4. 在上一步结果上 -4+0x16
    // 5. 以上一步结果作为读取地址 读取 64 字节数据
    if read_op_str != "" {
        // 即一系列 加、减、取指针 操作作为要读取类型的地址 通过以下规则来转换
        has_first_op := false
        for ptr_idx, op_str := range strings.Split(read_op_str, ".") {
            if ptr_idx > 0 {
                point_arg.AddExtraOp(argtype.OPC_READ_POINTER)
                point_arg.AddExtraOp(argtype.OPC_MOVE_POINTER_VALUE)
            }
            if op_str == "" {
                continue
            }
            v := op_str + "+"
            last_op := ""
            for {
                i := strings.IndexAny(v, "+-")
                if i < 0 {
                    break
                }
                op := string(v[i])
                token := string(v[0:i])
                v = v[i+1:]
                if token != "" {
                    if value, err := strconv.ParseUint(token, 0, 64); err == nil {
                        if !has_first_op {
                            panic(fmt.Sprintf("first op must be reg"))
                        }
                        if last_op == "-" {
                            point_arg.AddExtraOp(argtype.OPC_SUB_OFFSET.NewValue(value))
                        } else {
                            point_arg.AddExtraOp(argtype.OPC_ADD_OFFSET.NewValue(value))
                        }
                    } else {
                        reg_index := GetRegIndex(token)
                        point_arg.AddExtraOp(argtype.Add_READ_MOVE_REG(uint64(reg_index)))
                        if has_first_op {
                            if last_op == "-" {
                                point_arg.AddExtraOp(argtype.OPC_SUB_REG)
                            } else {
                                point_arg.AddExtraOp(argtype.OPC_ADD_REG)
                            }
                        }
                        if !has_first_op {
                            has_first_op = true
                        }
                    }
                }
                last_op = op
            }
        }
        point_arg.AddExtraOp(argtype.OPC_SAVE_ADDR)
    }
    return err
}

func (this *StackUprobeConfig) IsEnable() bool {
    return len(this.Points) > 0
}

func (this *StackUprobeConfig) SetArgFilterRule(arg_filter *[]ArgFilter) {
    this.arg_filter = arg_filter
}

func (this *StackUprobeConfig) SetDumpHex(dump_hex bool) {
    this.DumpHex = dump_hex
}

func (this *StackUprobeConfig) SetColor(color bool) {
    this.Color = color
}

func (this *StackUprobeConfig) GetSyscall() string {
    results := []string{}
    for _, point := range this.Points {
        if point.ToSyscall() {
            results = append(results, point.Name)
        }
    }
    return strings.Join(results, ",")
}

func (this *StackUprobeConfig) Parse_FileConfig(config *UprobeFileConfig) (err error) {
    for index, point_config := range config.Points {
        hook_point := &UprobeArgs{}
        hook_point.BindSyscall = false
        hook_point.ExitRead = false
        hook_point.Index = uint32(index)
        hook_point.LibPath = this.LibPath
        hook_point.RealFilePath = this.RealFilePath
        hook_point.NonElfOffset = this.NonElfOffset
        hook_point.Name = point_config.Name
        if point_config.Signal != "" {
            hook_point.KillSignal = util.ParseSignal(point_config.Signal)
        }

        // strstr / strstr+0x4 / 0xA94E8
        items := strings.Split(point_config.Name, "+")
        if len(items) == 1 {
            sym_or_off := items[0]
            if strings.HasPrefix(sym_or_off, "0x") {
                offset, err := strconv.ParseUint(sym_or_off, 0, 64)
                if err != nil {
                    return errors.New(fmt.Sprintf("parse for %s failed, err:%v", point_config.Name, err))
                }
                hook_point.Offset = offset
                hook_point.Symbol = ""
            } else {
                hook_point.Symbol = sym_or_off
            }
        } else if len(items) == 2 {
            hook_point.Symbol = items[0]
            sym_or_off := items[1]
            offset, err := strconv.ParseUint(sym_or_off, 0, 64)
            if err != nil {
                return errors.New(fmt.Sprintf("parse for %s failed, err:%v", point_config.Name, err))
            }
            hook_point.Offset = offset
        } else {
            return errors.New(fmt.Sprintf("parse for %s failed, err:%v", point_config.Name, err))
        }

        for arg_index, param := range point_config.Params {
            point_arg := param.GetPointArg(uint32(arg_index), EBPF_UPROBE_ENTER)
            hook_point.PointArgs = append(hook_point.PointArgs, point_arg)
        }
        this.Points = append(this.Points, hook_point)
    }
    return nil
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
    for point_index, config_str := range configs {
        exit_read := false
        bind_syscall := false
        if strings.HasSuffix(config_str, "]s") {
            // 临时方案 将 uprobe 用法绑定到 syscall 上
            config_str = config_str[:len(config_str)-1]
            bind_syscall = true
        }
        if strings.HasSuffix(config_str, "]ss") {
            // 两个s表示对于sys_exit也要进行详细输出
            config_str = config_str[:len(config_str)-2]
            exit_read = true
            bind_syscall = true
        }
        reg := regexp.MustCompile(`(\w+)(\+0x[[:xdigit:]]+)?(\[.+?\])?`)
        match := reg.FindStringSubmatch(config_str)

        if len(match) > 0 {
            hook_point := &UprobeArgs{}
            hook_point.BindSyscall = bind_syscall
            hook_point.ExitRead = exit_read
            hook_point.Index = uint32(point_index)
            hook_point.Offset = 0x0
            hook_point.LibPath = this.LibPath
            hook_point.RealFilePath = this.RealFilePath
            hook_point.NonElfOffset = this.NonElfOffset
            sym_or_off := match[1]
            hook_point.Name = sym_or_off
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
                    point_arg := NewUprobePointArg(arg_name, POINTER, uint32(arg_index))
                    if err := this.ParseArgType(arg_str, point_arg); err != nil {
                        return err
                    }
                    hook_point.PointArgs = append(hook_point.PointArgs, point_arg)
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
    logger       *log.Logger
    debug        bool
    arg_filter   *[]ArgFilter
    Enable       bool
    TraceMode    uint32
    PointArgs    []*SyscallPoint
    SysWhitelist []uint32
    SysBlacklist []uint32
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

func (this *SyscallConfig) GetSyscallPointByNR(nr uint32) *SyscallPoint {
    // 后面加个 map 吧 总感觉这样会比较慢
    for _, point_arg := range this.PointArgs {
        if point_arg.Nr == nr {
            return point_arg
        }
    }
    panic(fmt.Sprintf("unknown nr:%d", nr))
}

func (this *SyscallConfig) Parse_FileConfig(config *SyscallFileConfig) (err error) {
    for _, point_config := range config.Points {
        var a_point_args []*PointArg
        var b_point_args []*PointArg
        for arg_index, param := range point_config.Params {
            if param.Name == "ret" {
                // 需要告知用户 syscall 中参数名 ret 仅用于返回值
                point_arg := param.GetPointArg(REG_ARM64_MAX, EBPF_SYS_EXIT)
                b_point_args = append(b_point_args, point_arg)
                break
            }

            var point_type uint32
            switch param.More {
            case "", "enter":
                point_type = EBPF_SYS_ENTER
            case "exit":
                point_type = EBPF_SYS_EXIT
            case "all":
                point_type = EBPF_SYS_ALL
            default:
                panic(fmt.Sprintf("unknown point_type:%s", param.More))
            }
            point_arg := param.GetPointArg(uint32(arg_index), point_type)

            a_p := point_arg.Clone()
            a_p.SetGroupType(EBPF_SYS_ENTER)
            a_point_args = append(a_point_args, a_p)

            b_p := point_arg.Clone()
            b_p.SetGroupType(EBPF_SYS_EXIT)
            b_point_args = append(b_point_args, b_p)

        }
        point := &SyscallPoint{point_config.Nr, point_config.Name, a_point_args, b_point_args}
        this.PointArgs = append(this.PointArgs, point)
    }

    return nil
}

func (this *SyscallConfig) Parse_SysWhitelist(gconfig *GlobalConfig) {
    if gconfig.SysCall == "" && len(gconfig.ConfigFiles) == 0 {
        this.Enable = false
        return
    }
    this.Enable = true
    this.TraceMode = TRACE_COMMON
    items := strings.Split(gconfig.SysCall, ",")
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
        case "%exit":
            syscall_items = append(syscall_items, []string{"exit", "exit_group"}...)
        case "%sched":
            syscall_items = append(syscall_items, []string{"sched_setparam", "sched_setscheduler", "sched_getscheduler"}...)
            syscall_items = append(syscall_items, []string{"sched_getparam", "sched_setaffinity", "sched_getaffinity"}...)
            syscall_items = append(syscall_items, []string{"sched_yield", "sched_get_priority_max", "sched_get_priority_min"}...)
            syscall_items = append(syscall_items, []string{"sched_rr_get_interval", "sched_setattr", "sched_getattr"}...)
        case "%dup":
            syscall_items = append(syscall_items, []string{"dup", "dup3"}...)
        case "%epoll":
            syscall_items = append(syscall_items, []string{"epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2"}...)
        case "%stat":
            syscall_items = append(syscall_items, []string{"statfs", "fstatfs", "newfstatat", "fstat", "statx"}...)
        default:
            if v != "" {
                syscall_items = append(syscall_items, v)
            }
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
    if len(this.PointArgs) > 0 {
        // 这个分支是配置文件走
        if len(unique_items) == 0 {
            // 命令行中不指定任何 syscall 那么会认为配置文件中的所有syscall都生效
            // 这种是用户自定义syscall参数读取方式
            for _, point_arg := range this.PointArgs {
                this.SysWhitelist = append(this.SysWhitelist, point_arg.Nr)
            }
        } else {
            // 指定了 syscall 则只从预置配置中选取存在的syscall
            // 这种是使用预置配置
            for _, syscall_name := range unique_items {
                for _, point_arg := range this.PointArgs {
                    if point_arg.Name == syscall_name {
                        this.SysWhitelist = append(this.SysWhitelist, point_arg.Nr)
                    }
                }
            }
        }
        return
    }

    for _, v := range unique_items {
        var index_items [][]uint32
        syscall_name := v
        items := strings.SplitN(syscall_name, ":", 2)
        if len(items) == 2 {
            syscall_name = items[0]

            filter_groups := strings.Split(items[1], "|")
            for _, filter_group := range filter_groups {
                var items []uint32
                filter_names := strings.Split(filter_group, ".")
                for _, filter_name := range filter_names {
                    for _, arg_filter := range *this.arg_filter {
                        if arg_filter.Match(filter_name) {
                            items = append(items, arg_filter.Filter_index)
                        }
                    }
                }
                index_items = append(index_items, items)
            }
        }
        point := GetSyscallPointByName(syscall_name)
        for i, items := range index_items {
            str_a_idx := 0
            for _, point_arg := range point.EnterPointArgs {
                if point_arg.TypeIndex == STRING {
                    if str_a_idx == i {
                        for _, filter_index := range items {
                            if point_arg.ReadMore() {
                                point_arg.AddFilterIndex(filter_index)
                            }
                        }
                    }
                    str_a_idx += 1
                }
            }
            str_b_idx := 0
            for _, point_arg := range point.ExitPointArgs {
                if point_arg.TypeIndex == STRING {
                    if str_b_idx == i {
                        for _, filter_index := range items {
                            if point_arg.ReadMore() {
                                point_arg.AddFilterIndex(filter_index)
                            }
                        }
                    }
                    str_b_idx += 1
                }
            }
        }
        this.PointArgs = append(this.PointArgs, point)
        this.SysWhitelist = append(this.SysWhitelist, uint32(point.Nr))
    }
    if len(this.PointArgs) == 0 {
        this.Enable = false
    }
}

func (this *SyscallConfig) Parse_SysBlacklist(text string) {
    if text == "" {
        return
    }
    items := strings.Split(text, ",")
    for _, v := range items {
        point := GetSyscallPointByName(v)
        this.SysBlacklist = append(this.SysBlacklist, uint32(point.Nr))
    }
}

func (this *SyscallConfig) IsEnable() bool {
    return this.Enable
}

func (this *SyscallConfig) Info() string {
    var whitelist []string
    for _, v := range this.SysWhitelist {
        point := GetSyscallPointByNR(v)
        whitelist = append(whitelist, point.Name)
    }
    var blacklist []string
    for _, v := range this.SysBlacklist {
        point := GetSyscallPointByNR(v)
        blacklist = append(blacklist, point.Name)
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

    TraceGroup  uint32
    KillSignal  uint32
    TKillSignal uint32
    UnwindStack bool
    ManualStack bool
    StackSize   uint32
    ShowRegs    bool
    GetOff      bool
    RegName     string
    ExternalBTF string
    Is32Bit     bool
    Buffer      uint32
    MaxOp       uint32
    BrkPid      int
    BrkAddr     uint64
    BrkLen      uint64
    BrkType     uint32
    BrkKernel   bool
    Color       bool
    DumpHandle  *os.File
    FmtJson     bool
    DumpHex     bool
    ShowPC      bool
    ShowTime    bool
    ShowUid     bool

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

func (this *ModuleConfig) InitCommonConfig(gconfig *GlobalConfig) {

    this.MaxOp = gconfig.MaxOp
    this.Buffer = gconfig.Buffer
    this.UnwindStack = gconfig.UnwindStack
    this.ManualStack = gconfig.ManualStack
    if gconfig.StackSize&7 != 0 {
        panic(fmt.Sprintf("dump stack size %d is not 8-byte aligned.", gconfig.StackSize))
    }
    this.StackSize = gconfig.StackSize
    this.ShowRegs = gconfig.ShowRegs
    this.GetOff = gconfig.GetOff
    this.Debug = gconfig.Debug
    this.Is32Bit = false
    this.Color = gconfig.Color
    this.FmtJson = gconfig.FmtJson
    this.RegName = gconfig.RegName
    this.DumpHex = gconfig.DumpHex
    this.ShowPC = gconfig.ShowPC
    this.ShowTime = gconfig.ShowTime
    this.ShowUid = gconfig.ShowUid

    this.KillSignal = util.ParseSignal(gconfig.KillSignal)
    this.TKillSignal = util.ParseSignal(gconfig.TKillSignal)

    this.StackUprobeConf = &StackUprobeConfig{}
    this.StackUprobeConf.SetDumpHex(this.DumpHex)
    this.StackUprobeConf.SetColor(this.Color)
    this.StackUprobeConf.SetArgFilterRule(&this.ArgFilterRule)

    this.SysCallConf = &SyscallConfig{}
    this.SysCallConf.SetDebug(this.Debug)
    this.SysCallConf.SetLogger(this.logger)
    this.SysCallConf.SetArgFilterRule(&this.ArgFilterRule)
}

func (this *ModuleConfig) LoadConfig(gconfig *GlobalConfig) {

    // 一些配置文件有关的逻辑
    // 1. 无论 uprobe 还是 syscall 指定的配置即为要hook的
    // 2. syscall 有内置解析配置 需要配合命令行 -s/--syscall 使用
    // 3. 指定了 syscall 类型的配置 则不会采用内置配置 也会无视 -s/--syscall

    for _, file := range gconfig.ConfigFiles {
        content, err := ioutil.ReadFile(file)
        if err != nil {
            panic(err)
        }
        base_config := &FileConfig{}
        err = json.Unmarshal(content, base_config)
        if err != nil {
            panic(err)
        }
        switch base_config.Type {
        case "uprobe":
            config := &UprobeFileConfig{}
            err = json.Unmarshal(content, config)
            if err != nil {
                panic(err)
            }
            err = gconfig.Parse_Libinfo(config.Library, this.StackUprobeConf)
            if err != nil {
                panic(err)
            }
            err = this.StackUprobeConf.Parse_FileConfig(config)
            if err != nil {
                panic(err)
            }
        case "syscall":
            config := &SyscallFileConfig{}
            err = json.Unmarshal(content, config)
            if err != nil {
                panic(err)
            }
            err = this.SysCallConf.Parse_FileConfig(config)
            if err != nil {
                panic(err)
            }
        default:
            panic(fmt.Sprintf("unsupported config type %s", base_config.Type))
        }

    }
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
            arg_filter.Str_len = uint32(len(str_old))
            copy(arg_filter.Str_val[:], str_old)
        case "b", "black":
            arg_filter.Filter_type = BLACKLIST_FILTER
            str_old := []byte(items[1])
            if len(str_old) > 256 {
                panic(fmt.Sprintf("string is to long, max length is 256"))
            }
            arg_filter.Str_len = uint32(len(str_old))
            copy(arg_filter.Str_val[:], str_old)
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
    filter.signal = this.KillSignal
    filter.tsignal = this.TKillSignal
    return filter
}

func (this *ModuleConfig) GetConfigMap() ConfigMap {
    config := ConfigMap{}
    config.stackplz_pid = this.SelfPid
    if len(this.TNameWhitelist) > 0 {
        config.thread_whitelist = 1
    }
    this.logger.Printf("ConfigMap{stackplz_pid=%d,thread_whitelist=%d}", config.stackplz_pid, config.thread_whitelist)
    return config
}

func (this *ModuleConfig) DumpOpen(dump_name string) {
    if dump_name == "" {
        return
    }
    dir, _ := os.Getwd()
    dump_path := dir + "/" + dump_name
    // 提前打开文件
    f, err := os.Create(dump_path)
    if err != nil {
        panic("create dump file failed...")
    }
    this.DumpHandle = f
}

func (this *ModuleConfig) DumpClose() {
    // 关闭文件
    if this.DumpHandle != nil {
        err := this.DumpHandle.Close()
        if err != nil {
            panic(err)
        }
    }
}

var file_lock sync.Mutex

func (this *ModuleConfig) DumpRecord(event_index uint8, rec *perf.Record) bool {
    // 返回  是否需要dump
    if this.DumpHandle == nil {
        return false
    }
    // 将采集的数据按下面的格式进行记录
    // total_len|event_index|rec_type|rec_len|rec_raw
    total_len := uint32(1)
    rec_len := uint32(len(rec.RawSample))
    total_len += 4 + 4 + rec_len
    file_lock.Lock()
    defer file_lock.Unlock()

    var err error
    if err = binary.Write(this.DumpHandle, binary.LittleEndian, total_len); err != nil {
        panic(err)
    }
    if err = binary.Write(this.DumpHandle, binary.LittleEndian, event_index); err != nil {
        panic(err)
    }
    if err = binary.Write(this.DumpHandle, binary.LittleEndian, rec.RecordType); err != nil {
        panic(err)
    }
    if err = binary.Write(this.DumpHandle, binary.LittleEndian, rec_len); err != nil {
        panic(err)
    }
    if err = binary.Write(this.DumpHandle, binary.LittleEndian, rec.RawSample); err != nil {
        panic(err)
    }

    return true
}
