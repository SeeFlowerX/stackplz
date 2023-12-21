package event

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/user/config"
    "stackplz/user/util"
    "strings"
)

type SyscallEvent struct {
    ContextEvent
    UUID          string
    RegsBuffer    RegsBuf
    UnwindBuffer  UnwindBuf
    nr_point      *config.SysCallArgs
    nr_point_next *config.PointArgsConfig
    nr            config.Arg_nr
    lr            config.Arg_reg
    sp            config.Arg_reg
    pc            config.Arg_reg
    ret           uint64
    arg_str       string
}

type Arg_bytes = config.Arg_str

func (this *SyscallEvent) ParseContextSysEnterNext() (err error) {
    if this.mconf.Next {
        this.logger.Printf("ParseContextSysEnterNext RawSample:\n%s", util.HexDump(this.rec.RawSample, util.COLORRED))
    }
    this.logger.Printf("nr:%s", this.nr.Format())
    if err = binary.Read(this.buf, binary.LittleEndian, &this.lr); err != nil {
        panic(err)
    }
    this.logger.Printf("lr:%s", this.lr.Format())
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pc); err != nil {
        panic(err)
    }
    this.logger.Printf("pc:%s", this.pc.Format())
    if err = binary.Read(this.buf, binary.LittleEndian, &this.sp); err != nil {
        panic(err)
    }
    this.logger.Printf("sp:%s", this.sp.Format())
    // 根据调用号解析剩余参数
    this.nr_point_next = config.GetSyscallPointByNR(this.nr.Value)
    if this.nr_point_next.Name != "sendmsg" {
        panic("only sendmsg now")
    }
    var results []string
    for arg_index, point_arg := range this.nr_point_next.Args {
        var ptr config.Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            panic(err)
        }
        this.logger.Printf("arg_index:%d ptr:%s", arg_index, ptr.Format())
        switch point_arg.AliasType {
        case config.TYPE_MSGHDR:
            var arg_msghdr config.Arg_Msghdr
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_msghdr.Index); err != nil {
                panic(err)
            }
            this.logger.Printf("index=%d", arg_msghdr.Index)
            results = append(results, fmt.Sprintf("index=%d", arg_msghdr.Index))
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_msghdr.Len); err != nil {
                panic(err)
            }
            this.logger.Printf("len=%d", arg_msghdr.Len)
            results = append(results, fmt.Sprintf("len=%d", arg_msghdr.Len))
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_msghdr.Msghdr); err != nil {
                panic(err)
            }
            this.logger.Printf("msghdr={%s}", arg_msghdr.Format())
            results = append(results, arg_msghdr.Format())
            iov_len := arg_msghdr.Iovlen
            if iov_len > 6 {
                iov_len = 6
            }
            this.logger.Printf("iov_len={%d}", iov_len)
            for i := 0; i < int(iov_len); i++ {
                this.logger.Printf("iov_index=%d", i)

                var iov_ptr config.Arg_reg
                if err = binary.Read(this.buf, binary.LittleEndian, &iov_ptr); err != nil {
                    panic(err)
                }
                this.logger.Printf("iov_ptr:%s", iov_ptr.Format())

                var arg_iovec config.Arg_Iovec_Fix_t
                if err = binary.Read(this.buf, binary.LittleEndian, &arg_iovec.Arg_Iovec_Fix); err != nil {
                    panic(err)
                }
                this.logger.Printf("index:%d iovec={%s}", arg_iovec.Index, arg_iovec.Format())
                var iov_buf config.Arg_str
                if err = binary.Read(this.buf, binary.LittleEndian, &iov_buf); err != nil {
                    panic(err)
                }
                payload := make([]byte, iov_buf.Len)
                if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
                    panic(err)
                }
                arg_iovec.Payload = payload
                this.logger.Printf("payload={%s}", arg_iovec.Format())
                results = append(results, arg_iovec.Format())
            }
        }
    }
    this.arg_str = "(" + strings.Join(results, ", ") + ")"
    return nil
}

func (this *SyscallEvent) ParseContextSysEnter() (err error) {
    if err = binary.Read(this.buf, binary.LittleEndian, &this.lr); err != nil {
        panic(err)
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pc); err != nil {
        panic(err)
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.sp); err != nil {
        panic(err)
    }
    // 根据调用号解析剩余参数
    point := config.GetWatchPointByNR(this.nr.Value)
    nr_point, ok := (point).(*config.SysCallArgs)
    if !ok {
        panic(fmt.Sprintf("cast nr[%d] point to SysCallArgs failed", this.nr.Value))
    }
    this.nr_point = nr_point
    var results []string
    for _, point_arg := range this.nr_point.Args {
        var ptr config.Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            panic(err)
        }
        if point_arg.BaseType == config.TYPE_NUM {
            results = append(results, point_arg.Format(this.nr_point, ptr.Address))
            continue
        }
        base_arg_str := fmt.Sprintf("%s=0x%x", point_arg.ArgName, ptr.Address)
        point_arg.SetValue(base_arg_str)
        // 这一类参数要等执行结束后读取 这里只获取参数所对应的寄存器值就可以了
        if point_arg.PointFlag == config.SYS_EXIT {
            results = append(results, point_arg.ArgValue)
            continue
        }
        this.ParseArgByType(&point_arg, ptr)
        results = append(results, point_arg.ArgValue)
    }
    this.arg_str = "(" + strings.Join(results, ", ") + ")"
    return nil
}

func (this *SyscallEvent) ParseContextSysExit() (err error) {
    point := config.GetWatchPointByNR(this.nr.Value)
    nr_point, ok := (point).(*config.SysCallArgs)
    if !ok {
        panic(fmt.Sprintf("cast nr[%d] point to SysCallArgs failed", this.nr.Value))
    }
    this.nr_point = nr_point
    var results []string
    for _, point_arg := range this.nr_point.Args {
        var ptr config.Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            panic(fmt.Sprintf("binary.Read %d %s err:%v", this.nr.Value, util.B2STrim(this.Comm[:]), err))
        }
        if point_arg.BaseType == config.TYPE_NUM {
            results = append(results, point_arg.Format(this.nr_point, ptr.Address))
            continue
        }
        base_arg_str := fmt.Sprintf("%s=0x%x", point_arg.ArgName, ptr.Address)
        point_arg.SetValue(base_arg_str)
        if point_arg.PointFlag != config.SYS_EXIT {
            results = append(results, point_arg.ArgValue)
            continue
        }
        this.ParseArgByType(&point_arg, ptr)
        results = append(results, point_arg.ArgValue)
    }
    // 处理返回参数
    var ptr config.Arg_reg
    if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
        panic(err)
    }
    point_arg := this.nr_point.Ret
    if point_arg.BaseType == config.TYPE_NUM {
        point_arg.SetValue(point_arg.Format(this.nr_point, ptr.Address))
    } else {
        point_arg.SetValue(fmt.Sprintf("0x%x", ptr.Address))
    }
    if point_arg.BaseType != config.TYPE_NUM {
        this.ParseArgByType(&point_arg, ptr)
    }
    if len(results) == 0 {
        results = append(results, "(void)")
    }
    this.arg_str = fmt.Sprintf("(%s => %s)", point_arg.ArgValue, strings.Join(results, ", "))
    return nil
}

func (this *SyscallEvent) ParseContext() (err error) {
    // 处理参数 常规参数的构成 是 索引 + 值
    if err = binary.Read(this.buf, binary.LittleEndian, &this.nr); err != nil {
        panic(err)
    }
    if this.EventId == SYSCALL_ENTER {
        // 是否有不执行 sys_exit 的情况 ?
        // 有的调用耗时 也有可能 暂时还是把执行结果分开输出吧
        if this.mconf.Next {
            this.ParseContextSysEnterNext()
        } else {
            this.ParseContextSysEnter()
        }
    } else if this.EventId == SYSCALL_EXIT {
        this.ParseContextSysExit()
    } else {
        panic(fmt.Sprintf("SyscallEvent.ParseContext() failed, EventId:%d", this.EventId))
    }
    this.ParsePadding()
    err = this.ParseContextStack()
    if err != nil {
        panic(fmt.Sprintf("ParseContextStack err:%v", err))
    }
    return nil
}

func (this *SyscallEvent) GetUUID() string {
    s := fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
    if this.mconf.ShowTime {
        s = fmt.Sprintf("%d|%s", this.Ts, s)
    }
    if this.mconf.ShowUid {
        s = fmt.Sprintf("%d|%s", this.Uid, s)
    }
    return s
}

func (this *SyscallEvent) JsonString(stack_str string) string {
    if this.EventId == SYSCALL_ENTER {
        v := config.SyscallFmt{}
        v.Ts = this.Ts
        v.Event = "sys_enter"
        v.HostTid = this.HostTid
        v.HostPid = this.HostPid
        v.Tid = this.Tid
        v.Pid = this.Pid
        v.Uid = this.Uid
        v.Comm = util.B2STrim(this.Comm[:])
        v.Argnum = this.Argnum
        v.Stack = stack_str
        v.NR = this.nr_point.PointName
        v.LR = fmt.Sprintf("0x%x", this.lr.Address)
        v.SP = fmt.Sprintf("0x%x", this.sp.Address)
        v.PC = fmt.Sprintf("0x%x", this.pc.Address)
        v.Arg_str = this.arg_str
        data, err := json.Marshal(v)
        if err != nil {
            panic(err)
        }
        return string(data)
    } else {
        v := config.SyscallExitFmt{}
        v.Ts = this.Ts
        v.Event = "sys_exit"
        v.HostTid = this.HostTid
        v.HostPid = this.HostPid
        v.Tid = this.Tid
        v.Pid = this.Pid
        v.Uid = this.Uid
        v.Comm = util.B2STrim(this.Comm[:])
        v.Argnum = this.Argnum
        v.Stack = stack_str
        v.NR = this.nr_point.PointName
        v.Arg_str = this.arg_str
        data, err := json.Marshal(v)
        if err != nil {
            panic(err)
        }
        return string(data)
    }
}

func (this *SyscallEvent) String() string {
    stack_str := ""
    if this.EventId == SYSCALL_ENTER {
        stack_str = this.GetStackTrace(stack_str)
    }
    if this.mconf.FmtJson {
        return this.JsonString(stack_str)
    }
    var base_str string
    base_str = fmt.Sprintf("[%s] nr:%s%s", this.GetUUID(), this.nr_point.PointName, this.arg_str)
    if this.EventId == SYSCALL_ENTER {
        var lr_str string
        var pc_str string
        if this.mconf.GetOff {
            lr_str = fmt.Sprintf("LR:0x%x(%s)", this.lr.Address, this.GetOffset(this.lr.Address))
            pc_str = fmt.Sprintf("PC:0x%x(%s)", this.pc.Address, this.GetOffset(this.pc.Address))
        } else {
            lr_str = fmt.Sprintf("LR:0x%x", this.lr.Address)
            pc_str = fmt.Sprintf("PC:0x%x", this.pc.Address)
        }
        base_str = fmt.Sprintf("%s %s %s SP:0x%x", base_str, lr_str, pc_str, this.sp.Address)
    }

    return base_str + stack_str
}

func (this *SyscallEvent) Clone() IEventStruct {
    event := new(SyscallEvent)
    return event
}
