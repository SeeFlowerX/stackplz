package event

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/user/config"
    "stackplz/user/util"
    "strconv"
    "strings"
    "time"
)

type LibArg struct {
    Abi       uint64
    Regs      [33]uint64
    StackSize uint64
    DynSize   uint64
}

type UnwindBuf struct {
    Abi       uint64
    Regs      [33]uint64
    StackSize uint64
    Data      []byte
    DynSize   uint64
}

func (this *UnwindBuf) GetLibArg() *LibArg {
    arg := &LibArg{}
    arg.Abi = this.Abi
    arg.Regs = this.Regs
    arg.StackSize = this.StackSize
    arg.DynSize = this.DynSize
    return arg
}

func (this *UnwindBuf) ParseContext(buf *bytes.Buffer) (err error) {
    if err = binary.Read(buf, binary.LittleEndian, &this.Abi); err != nil {
        return err
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Regs); err != nil {
        return err
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.StackSize); err != nil {
        return err
    }

    stack_data := make([]byte, this.StackSize)
    if err = binary.Read(buf, binary.LittleEndian, &stack_data); err != nil {
        return err
    }
    this.Data = stack_data

    if err = binary.Read(buf, binary.LittleEndian, &this.DynSize); err != nil {
        return err
    }
    return nil
}

type RegsBuf struct {
    Abi  uint64
    Regs [33]uint64
}

func (this *RegsBuf) ParseContext(buf *bytes.Buffer) (err error) {
    if err = binary.Read(buf, binary.LittleEndian, &this.Abi); err != nil {
        return err
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Regs); err != nil {
        return err
    }
    return nil
}

type ContextEvent struct {
    CommonEvent
    Ts            uint64
    EventId       uint32
    HostTid       uint32
    HostPid       uint32
    Tid           uint32
    Pid           uint32
    Uid           uint32
    Comm          [16]byte
    Argnum        uint8
    Padding       [7]byte
    Part_raw_size uint32

    Stackinfo    string
    RegsBuffer   RegsBuf
    UnwindBuffer *UnwindBuf
    RegName      string
}

func (this *ContextEvent) ParseArgStruct(buf *bytes.Buffer, arg config.ArgFormatter) string {
    if err := binary.Read(buf, binary.LittleEndian, arg); err != nil {
        this.logger.Printf("ContextEvent EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
        time.Sleep(5 * 100 * time.Millisecond)
        panic(err)
    }
    return arg.Format()
}

func (this *ContextEvent) ParseArgStructHex(buf *bytes.Buffer, arg config.ArgHexFormatter) string {
    if err := binary.Read(buf, binary.LittleEndian, arg); err != nil {
        this.logger.Printf("ContextEvent EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
        time.Sleep(5 * 100 * time.Millisecond)
        panic(err)
    }
    return arg.HexFormat()
}

func (this *ContextEvent) GetOffset(addr uint64) string {
    return maps_helper.GetOffset(this.Pid, addr)
}

func (this *ContextEvent) NewSyscallEvent() IEventStruct {
    event := &SyscallEvent{ContextEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewSyscallEvent.ParseContext() err:%v", err))
    }
    return event
}

func (this *ContextEvent) NewUprobeEvent() IEventStruct {
    event := &UprobeEvent{ContextEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewUprobeEvent.ParseContext() err:%v", err))
    }
    return event
}

func (this *ContextEvent) NewBrkEvent() IEventStruct {
    event := &BrkEvent{ContextEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewUprobeEvent.ParseContext() err:%v", err))
    }
    return event
}

func (this *ContextEvent) String() (s string) {
    s += fmt.Sprintf("event_id:%d ts:%d", this.EventId, this.Ts)
    s += fmt.Sprintf(", host_pid:%d, host_tid:%d", this.HostPid, this.HostTid)
    s += fmt.Sprintf(", Uid:%d, pid:%d, tid:%d", this.Uid, this.Pid, this.Tid)
    s += fmt.Sprintf(", Comm:%s, argnum:%d", util.B2STrim(this.Comm[:]), this.Argnum)
    return s
}

func (this *ContextEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.Pid, this.Tid)
}

func (this *ContextEvent) GetEventId() uint32 {
    return this.EventId
}

func (this *ContextEvent) ParsePadding() (err error) {
    // 好在 SampleSize 是明确的 这样我们可以正确计算下一部分 perf 数据起始位置
    // ebpf库改为全部读取之后 这里的 4 是 PERF_SAMPLE_RAW 的 size
    padding_size := this.rec.SampleSize + 4 - uint32(this.buf.Cap()-this.buf.Len())
    if padding_size > 0 {
        payload := make([]byte, padding_size)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            this.logger.Printf("ContextEvent EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
            panic(err)
        }
    }
    return nil
}

func (this *ContextEvent) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.rec.SampleSize); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Ts); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.EventId); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.HostTid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.HostPid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Uid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Comm); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Argnum); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Padding); err != nil {
        return err
    }
    // 这一类的说明都是要关注的
    maps_helper.UpdatePidList(this.Pid)
    return nil
}

func (this *ContextEvent) Clone() IEventStruct {
    event := new(ContextEvent)
    return event
}

func (this *ContextEvent) ParseArgByType(point_arg *config.PointArg, ptr config.Arg_reg) {
    var err error
    if ptr.Address == 0 {
        point_arg.AppendValue("(NULL)")
        return
    }
    // 这个函数先处理基础类型

    if point_arg.Type == config.TYPE_POINTER {
        // BUFFER 比较特殊 单独处理
        if point_arg.AliasType == config.TYPE_BUFFER_T {
            point_arg.AppendValue(fmt.Sprintf("(*0x%x)%s", ptr.Address, this.ParseArg(point_arg, ptr)))
            return
        }
        // 对于指针类型 需要先处理
        var next_ptr config.Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &next_ptr); err != nil {
            panic(err)
        }
        // if this.mconf.Debug {
        //     this.logger.Printf("[buf] len:%d cap:%d off:%d", this.buf.Len(), this.buf.Cap(), this.buf.Cap()-this.buf.Len())
        // }
        if next_ptr.Address == 0 {
            point_arg.AppendValue("(0x0)")
            return
        }
        if point_arg.AliasType == config.TYPE_POINTER {
            // 这种不再需要进一步解析了
            point_arg.AppendValue(fmt.Sprintf("(0x%x)", next_ptr.Address))
        } else {
            // pointer + struct
            point_arg.AppendValue(fmt.Sprintf("(*0x%x)%s", next_ptr.Address, this.ParseArg(point_arg, next_ptr)))
        }
    } else {
        // 这种一般就是特殊类型 获取结构体了
        point_arg.AppendValue(this.ParseArg(point_arg, ptr))
    }
}
func (this *ContextEvent) ParseArg(point_arg *config.PointArg, ptr config.Arg_reg) string {
    var err error
    switch point_arg.AliasType {
    case config.TYPE_NONE:
        panic("AliasType TYPE_NONE can not be here")
    case config.TYPE_NUM:
        panic("AliasType TYPE_NUM can not be here")
    case config.TYPE_BUFFER_T:
        var arg config.Arg_Buffer_t
        if err = binary.Read(this.buf, binary.LittleEndian, &arg.Arg_str); err != nil {
            panic(err)
        }
        payload := make([]byte, arg.Len)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            panic(err)
        }
        arg.Payload = payload
        if this.mconf.DumpHex {
            return arg.HexFormat(this.mconf.Color)
        } else {
            return arg.Format()
        }
    case config.TYPE_STRING:
        var arg config.Arg_str
        if err = binary.Read(this.buf, binary.LittleEndian, &arg); err != nil {
            panic(err)
        }
        payload := make([]byte, arg.Len)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            panic(err)
        }
        return fmt.Sprintf("(%s)", util.B2STrim(payload))
    case config.TYPE_STRING_ARR:
        var arg_str_arr config.Arg_str_arr
        if err = binary.Read(this.buf, binary.LittleEndian, &arg_str_arr); err != nil {
            panic(err)
        }
        var str_arr []string
        for i := 0; i < int(arg_str_arr.Count); i++ {
            var len uint32
            if err = binary.Read(this.buf, binary.LittleEndian, &len); err != nil {
                panic(err)
            }
            payload := make([]byte, len)
            if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
                panic(err)
            }
            str_arr = append(str_arr, util.B2STrim(payload))
        }
        return fmt.Sprintf("[%s]", strings.Join(str_arr, ", "))
    case config.TYPE_POINTER:
        // 先解析参数寄存器本身的值
        var ptr_value config.Arg_reg
        // 再解析参数寄存器指向地址的值
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr_value); err != nil {
            panic(err)
        }
        return fmt.Sprintf("(0x%x)", ptr_value.Address)
    case config.TYPE_SIGSET:
        var sigs [8]uint32
        if err = binary.Read(this.buf, binary.LittleEndian, &sigs); err != nil {
            panic(err)
        }
        var fmt_sigs []string
        for i := 0; i < len(sigs); i++ {
            fmt_sigs = append(fmt_sigs, fmt.Sprintf("0x%x", sigs[i]))
        }
        return fmt.Sprintf("(sigs=[%s])", strings.Join(fmt_sigs, ","))
    case config.TYPE_POLLFD:
        return this.ParseArgStruct(this.buf, &config.Arg_Pollfd{})
    case config.TYPE_STRUCT:
        payload := make([]byte, point_arg.Size)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            panic(err)
        }
        return fmt.Sprintf("([hex]%x)", payload)
    case config.TYPE_TIMEZONE:
        return this.ParseArgStruct(this.buf, &config.Arg_TimeZone_t{})
    case config.TYPE_PTHREAD_ATTR:
        return this.ParseArgStruct(this.buf, &config.Arg_Pthread_attr_t{})
    case config.TYPE_TIMEVAL:
        return this.ParseArgStruct(this.buf, &config.Arg_Timeval{})
    case config.TYPE_TIMESPEC:
        return this.ParseArgStruct(this.buf, &config.Arg_Timespec{})
    case config.TYPE_STAT:
        return this.ParseArgStruct(this.buf, &config.Arg_Stat_t{})
    case config.TYPE_STATFS:
        return this.ParseArgStruct(this.buf, &config.Arg_Statfs_t{})
    case config.TYPE_SIGACTION:
        return this.ParseArgStruct(this.buf, &config.Arg_Sigaction{})
    case config.TYPE_UTSNAME:
        return this.ParseArgStruct(this.buf, &config.Arg_Utsname{})
    case config.TYPE_SOCKADDR:
        return this.ParseArgStruct(this.buf, &config.Arg_RawSockaddrUnix{})
    case config.TYPE_RUSAGE:
        return this.ParseArgStruct(this.buf, &config.Arg_Rusage{})
    case config.TYPE_IOVEC:
        // IOVEC 这里本质上是一个数组 还不太一样...
        var arg config.Arg_Iovec_t
        if err = binary.Read(this.buf, binary.LittleEndian, &arg.Arg_Iovec); err != nil {
            panic(err)
        }
        payload := make([]byte, arg.BufLen)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            panic(err)
        }
        arg.Payload = payload
        return arg.Format()
    case config.TYPE_EPOLLEVENT:
        return this.ParseArgStruct(this.buf, &config.Arg_EpollEvent{})
    case config.TYPE_SYSINFO:
        return this.ParseArgStruct(this.buf, &config.Arg_Sysinfo_t{})
    case config.TYPE_SIGINFO:
        return this.ParseArgStruct(this.buf, &config.Arg_SigInfo{})
    case config.TYPE_MSGHDR:
        return this.ParseArgStruct(this.buf, &config.Arg_Msghdr{})
    case config.TYPE_ITIMERSPEC:
        return this.ParseArgStruct(this.buf, &config.Arg_ItTmerspec{})
    case config.TYPE_STACK_T:
        return this.ParseArgStruct(this.buf, &config.Arg_Stack_t{})
    default:
        panic(fmt.Sprintf("unknown point_arg.AliasType %d", point_arg.AliasType))
    }
}

func (this *ContextEvent) GetStackTrace(s string) string {
    if this.RegName != "" {
        // 如果设置了寄存器名字 那么尝试从获取到的寄存器数据中取值计算偏移
        // 当然前提是取了寄存器数据
        var tmp_regs [33]uint64
        if this.rec.ExtraOptions.UnwindStack {
            tmp_regs = this.UnwindBuffer.Regs
        } else {
            tmp_regs = this.RegsBuffer.Regs
        }
        has_reg_value := false
        var regvalue uint64
        if strings.HasPrefix(this.RegName, "x") {
            parts := strings.SplitN(this.RegName, "x", 2)
            regno, _ := strconv.ParseUint(parts[1], 10, 32)
            if regno >= 0 && regno <= uint64(config.REG_ARM64_X29) {
                // 取到对应的寄存器值
                regvalue = tmp_regs[regno]
                has_reg_value = true
            }
        } else if this.RegName == "lr" {
            regvalue = tmp_regs[config.REG_ARM64_LR]
            has_reg_value = true
        }
        if has_reg_value {
            // 读取maps 获取偏移信息
            info, err := util.ParseReg(this.Pid, regvalue)
            if err != nil {
                fmt.Printf("ParseReg for %s=0x%x failed", this.RegName, regvalue)
            } else {
                s += fmt.Sprintf(", Reg %s Info:\n%s", this.RegName, info)
            }
        }
    }
    if this.rec.ExtraOptions.ShowRegs {
        var tmp_regs [33]uint64
        if this.rec.ExtraOptions.UnwindStack {
            tmp_regs = this.UnwindBuffer.Regs
        } else {
            tmp_regs = this.RegsBuffer.Regs
        }
        regs := make(map[string]string)
        for regno := 0; regno <= int(config.REG_ARM64_X29); regno++ {
            regs[fmt.Sprintf("x%d", regno)] = fmt.Sprintf("0x%x", tmp_regs[regno])
        }
        regs["lr"] = fmt.Sprintf("0x%x", tmp_regs[config.REG_ARM64_LR])
        regs["sp"] = fmt.Sprintf("0x%x", tmp_regs[config.REG_ARM64_SP])
        regs["pc"] = fmt.Sprintf("0x%x", tmp_regs[config.REG_ARM64_PC])
        regs_info, err := json.Marshal(regs)
        if err != nil {
            regs_info = make([]byte, 0)
        }
        s += ", Regs:\n" + string(regs_info)
    }
    if this.Stackinfo != "" {
        if this.rec.ExtraOptions.ShowRegs {
            s += fmt.Sprintf("\nStackinfo:\n%s", this.Stackinfo)
        } else {
            s += fmt.Sprintf(", Stackinfo:\n%s", this.Stackinfo)
        }
    }
    return s
}

func (this *ContextEvent) ParseContextStack() (err error) {
    this.Stackinfo = ""
    if this.rec.ExtraOptions.UnwindStack {
        // 读取完整的栈数据和寄存器数据 并解析为 UnwindBuf 结构体
        this.UnwindBuffer = &UnwindBuf{}
        err = this.UnwindBuffer.ParseContext(this.buf)
        if err != nil {
            panic(fmt.Sprintf("UnwindStack ParseContext failed, err:%v", err))
        }
        // 立刻获取堆栈信息 对于某些hook点前后可能导致maps发生变化的 堆栈可能不准确
        // 这里后续可以调整为只dlopen一次 拿到要调用函数的handle 不要重复dlopen
        content, err := util.ReadMapsByPid(this.Pid)
        if err != nil {
            // 直接读取 maps 失败 那么从 mmap2 事件中获取
            // 根据测试结果 有这样的情况 -> 即 fork 产生的子进程 那么应该查找其父进程 mmap2 事件
            maps_helper.SetLogger(this.logger)
            info, err := maps_helper.GetStack(this.Pid, this.UnwindBuffer)
            if err != nil {
                // this.logger.Printf("Error when opening file:%v", err)
                this.logger.Printf("Error when GetStack:%v", err)
            } else {
                this.Stackinfo = info
            }
            return nil
        }
        this.Stackinfo = ParseStack(content, this.UnwindBuffer)
    } else if this.rec.ExtraOptions.ShowRegs {
        err = this.RegsBuffer.ParseContext(this.buf)
        if err != nil {
            panic(fmt.Sprintf("UnwindStack ParseContext failed, err:%v", err))
        }
    }
    return nil
}
