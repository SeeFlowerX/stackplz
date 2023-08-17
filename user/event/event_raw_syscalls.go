package event

import (
    "encoding/binary"
    "fmt"
    "net"
    "stackplz/user/config"
    "stackplz/user/util"
    "strings"
    "syscall"
    "unsafe"
)

type Timespec struct {
    TvSec  uint64 /* seconds */
    TvNsec uint64 /* nanoseconds */
}

func (this *Timespec) String() string {
    return fmt.Sprintf("seconds=%d,nanoseconds=%d", this.TvSec, this.TvNsec)
}

type SyscallEvent struct {
    ContextEvent
    WaitExit     bool
    UUID         string
    Stackinfo    string
    RegsBuffer   RegsBuf
    UnwindBuffer UnwindBuf
    nr_point     *config.SysCallArgs
    nr           Arg_nr
    lr           Arg_reg
    sp           Arg_reg
    pc           Arg_reg
    ret          uint64
    args         [6]uint64
    arg_str      string
}

type IArg interface {
    Format() string
}

type Arg_nr struct {
    Index uint8
    Value uint32
}
type Arg_probe_index struct {
    Index uint8
    Value uint32
}
type Arg_reg struct {
    Index   uint8
    Address uint64
}

func (this *Arg_reg) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("[debug index:%d address:0x%x]", this.Index, this.Address))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_str struct {
    Index uint8
    Len   uint32
}
type Arg_str_arr struct {
    Index uint8
    Count uint8
}
type Arg_Timespec struct {
    Index uint8
    Len   uint32
    syscall.Timespec
}

func (this *Arg_Timespec) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("sec=%d", this.Sec))
    fields = append(fields, fmt.Sprintf("nsec=%d", this.Nsec))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_TimeZone_t struct {
    Index uint8
    Len   uint32
    config.TimeZone_t
}

func (this *Arg_TimeZone_t) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("tz_minuteswest=%d", this.Tz_minuteswest))
    fields = append(fields, fmt.Sprintf("tz_dsttime=%d", this.Tz_dsttime))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Pthread_attr_t struct {
    Index uint8
    Len   uint32
    config.Pthread_attr_t
}

type Arg_Buffer_t struct {
    Arg_str
    Payload []byte
}

func (this *Arg_Buffer_t) Format() string {
    // hexdump := util.HexDumpPure(this.Payload)
    hexdump := util.PrettyByteSlice(this.Payload)
    return fmt.Sprintf("(%s)", hexdump)
}

func (this *Arg_Buffer_t) HexFormat(color bool) string {
    var hexdump string
    if color {
        hexdump = util.HexDumpGreen(this.Payload)
    } else {
        hexdump = util.HexDumpPure(this.Payload)
    }
    return fmt.Sprintf("(\n%s)", hexdump)
}

type Arg_Timeval struct {
    Index uint8
    Len   uint32
    syscall.Timeval
}

func (this *Arg_Timeval) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("sec=%d", this.Sec))
    fields = append(fields, fmt.Sprintf("usec=%d", this.Usec))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Sigaction struct {
    Index uint8
    Len   uint32
    config.Sigaction
}
type Arg_Pollfd struct {
    Index uint8
    Len   uint32
    config.Pollfd
}
type Arg_Stat_t struct {
    Index uint8
    Len   uint32
    syscall.Stat_t
}
type Arg_Statfs_t struct {
    Index uint8
    Len   uint32
    syscall.Statfs_t
}

// vscode 配置下面的部分 这样才有正确的代码提示
// "go.toolsEnvVars": {
//     "GOOS": "android",
//     "GOARCH": "arm64"
// }

func (this *Arg_Stat_t) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("dev=%d", this.Dev))
    fields = append(fields, fmt.Sprintf("ino=%d", this.Ino))
    fields = append(fields, fmt.Sprintf("nlink=%d", this.Nlink))
    fields = append(fields, fmt.Sprintf("mode=%d", this.Mode))
    fields = append(fields, fmt.Sprintf("uid=%d", this.Uid))
    fields = append(fields, fmt.Sprintf("gid=%d", this.Gid))
    fields = append(fields, fmt.Sprintf("rdev=%d", this.Rdev))
    fields = append(fields, fmt.Sprintf("x__pad1=%d", this.X__pad1))
    fields = append(fields, fmt.Sprintf("size=%d", this.Size))
    fields = append(fields, fmt.Sprintf("blksize=%d", this.Blksize))
    fields = append(fields, fmt.Sprintf("x__pad2=%d", this.X__pad2))
    fields = append(fields, fmt.Sprintf("blocks=%d", this.Blocks))
    fields = append(fields, fmt.Sprintf("atim={tv_sec=%d, tv_nsec=%d}", this.Atim.Sec, this.Atim.Nsec))
    fields = append(fields, fmt.Sprintf("mtim={tv_sec=%d, tv_nsec=%d}", this.Mtim.Sec, this.Mtim.Nsec))
    fields = append(fields, fmt.Sprintf("ctim={tv_sec=%d, tv_nsec=%d}", this.Ctim.Sec, this.Ctim.Nsec))
    fields = append(fields, fmt.Sprintf("x__glibc_reserved=0x%x,0x%x", this.X__glibc_reserved[0], this.X__glibc_reserved[1]))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}
func (this *Arg_Statfs_t) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("type=%d", this.Type))
    fields = append(fields, fmt.Sprintf("bsize=%d", this.Bsize))
    fields = append(fields, fmt.Sprintf("blocks=%d", this.Blocks))
    fields = append(fields, fmt.Sprintf("bfree=%d", this.Bfree))
    fields = append(fields, fmt.Sprintf("bavail=%d", this.Bavail))
    fields = append(fields, fmt.Sprintf("files=%d", this.Files))
    fields = append(fields, fmt.Sprintf("ffree=%d", this.Ffree))
    fields = append(fields, fmt.Sprintf("fsid=0x%x,0x%x", this.Fsid.X__val[0], this.Fsid.X__val[1]))
    fields = append(fields, fmt.Sprintf("namelen=%d", this.Namelen))
    fields = append(fields, fmt.Sprintf("frsize=%d", this.Frsize))
    fields = append(fields, fmt.Sprintf("flags=%d", this.Flags))
    fields = append(fields, fmt.Sprintf("spare=0x%x,0x%x,0x%x,0x%x", this.Spare[0], this.Spare[1], this.Spare[2], this.Spare[3]))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

func (this *Arg_Sigaction) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("sa_handler=0x%x", this.Sa_handler))
    fields = append(fields, fmt.Sprintf("sa_sigaction=0x%x", this.Sa_sigaction))
    fields = append(fields, fmt.Sprintf("sa_mask=0x%x", this.Sa_mask))
    fields = append(fields, fmt.Sprintf("sa_flags=0x%x", this.Sa_flags))
    fields = append(fields, fmt.Sprintf("sa_restorer=0x%x", this.Sa_restorer))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Utsname struct {
    Index uint8
    Len   uint32
    syscall.Utsname
}
type Arg_RawSockaddrUnix struct {
    Index uint8
    Len   uint32
    syscall.RawSockaddrUnix
}

func (this *Arg_RawSockaddrUnix) Format() string {
    var fields []string
    if this.Family == syscall.AF_FILE {
        fields = append(fields, "family=AF_FILE")
        fields = append(fields, fmt.Sprintf("path=%s", B2S(this.Path[:])))
    } else if this.Family == syscall.AF_INET {
        fields = append(fields, "family=AF_INET")
        sockaddr := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&this.RawSockaddrUnix))
        fields = append(fields, fmt.Sprintf("port=%d", sockaddr.Port))
        fields = append(fields, fmt.Sprintf("addr=%s", net.IP(sockaddr.Addr[:]).String()))
        fields = append(fields, fmt.Sprintf("zero=%x", sockaddr.Zero))
    } else if this.Family == syscall.AF_INET6 {
        fields = append(fields, "family=AF_INET6")
        sockaddr6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&this.RawSockaddrUnix))
        fields = append(fields, fmt.Sprintf("port=%d", sockaddr6.Port))
        fields = append(fields, fmt.Sprintf("flowinfo=%d", sockaddr6.Flowinfo))
        // 好像还是会解析成ipv4
        fields = append(fields, fmt.Sprintf("addr=%s", net.IP(sockaddr6.Addr[:]).String()))
        fields = append(fields, fmt.Sprintf("scope_id=%d", sockaddr6.Scope_id))
    } else if this.Family == syscall.AF_UNSPEC {
        // 暂时不知道这个怎么解析比较好
        fields = append(fields, "family=AF_UNSPEC")
        fields = append(fields, fmt.Sprintf("path=\n%s", util.HexDump(I2B(this.Path[:]), util.COLORGREEN)))
    } else {
        fields = append(fields, fmt.Sprintf("family=0x%x", this.Family))
        fields = append(fields, fmt.Sprintf("path=\n%s", util.HexDump(I2B(this.Path[:]), util.COLORGREEN)))
    }
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Iovec struct {
    Index  uint8
    Base   uint64
    BufLen uint64
}

type Arg_Iovec_t struct {
    Arg_Iovec
    Payload []byte
}

func (this *Arg_Iovec_t) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("base=0x%x", this.Base))
    fields = append(fields, fmt.Sprintf("len=0x%x", this.BufLen))
    fields = append(fields, fmt.Sprintf("buf=(%s)", util.PrettyByteSlice(this.Payload)))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_EpollEvent struct {
    Index uint8
    Len   uint32
    syscall.EpollEvent
}

func (this *Arg_EpollEvent) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("events=0x%x", this.Events))
    fields = append(fields, fmt.Sprintf("_=*"))
    fields = append(fields, fmt.Sprintf("fd=%d", this.Fd))
    fields = append(fields, fmt.Sprintf("pad=%d", this.Pad))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Rusage struct {
    Index uint8
    Len   uint32
    syscall.Rusage
}

func (this *Arg_Rusage) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("utime=timeval{sec=%d, usec=%d}", this.Utime.Sec, this.Utime.Usec))
    fields = append(fields, fmt.Sprintf("stime=timeval{sec=%d, usec=%d}", this.Stime.Sec, this.Stime.Usec))
    fields = append(fields, fmt.Sprintf("Maxrss=0x%x", this.Maxrss))
    fields = append(fields, fmt.Sprintf("Ixrss=0x%x", this.Ixrss))
    fields = append(fields, fmt.Sprintf("Idrss=0x%x", this.Idrss))
    fields = append(fields, fmt.Sprintf("Isrss=0x%x", this.Isrss))
    fields = append(fields, fmt.Sprintf("Minflt=0x%x", this.Minflt))
    fields = append(fields, fmt.Sprintf("Majflt=0x%x", this.Majflt))
    fields = append(fields, fmt.Sprintf("Nswap=0x%x", this.Nswap))
    fields = append(fields, fmt.Sprintf("Inblock=0x%x", this.Inblock))
    fields = append(fields, fmt.Sprintf("Oublock=0x%x", this.Oublock))
    fields = append(fields, fmt.Sprintf("Msgsnd=0x%x", this.Msgsnd))
    fields = append(fields, fmt.Sprintf("Msgrcv=0x%x", this.Msgrcv))
    fields = append(fields, fmt.Sprintf("Nsignals=0x%x", this.Nsignals))
    fields = append(fields, fmt.Sprintf("Nvcsw=0x%x", this.Nvcsw))
    fields = append(fields, fmt.Sprintf("Nivcsw=0x%x", this.Nivcsw))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Sysinfo_t struct {
    Index uint8
    Len   uint32
    syscall.Sysinfo_t
}

func (this *Arg_Sysinfo_t) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("uptime=0x%x", this.Uptime))
    fields = append(fields, fmt.Sprintf("loads=0x%x,0x%x,0x%x", this.Loads[0], this.Loads[1], this.Loads[2]))
    fields = append(fields, fmt.Sprintf("totalram=0x%x", this.Totalram))
    fields = append(fields, fmt.Sprintf("freeram=0x%x", this.Freeram))
    fields = append(fields, fmt.Sprintf("sharedram=0x%x", this.Sharedram))
    fields = append(fields, fmt.Sprintf("bufferram=0x%x", this.Bufferram))
    fields = append(fields, fmt.Sprintf("totalswap=0x%x", this.Totalswap))
    fields = append(fields, fmt.Sprintf("freeswap=0x%x", this.Freeswap))
    fields = append(fields, fmt.Sprintf("procs=0x%x", this.Procs))
    fields = append(fields, fmt.Sprintf("pad=0x%x", this.Pad))
    fields = append(fields, fmt.Sprintf("totalhigh=0x%x", this.Totalhigh))
    fields = append(fields, fmt.Sprintf("freehigh=0x%x", this.Freehigh))
    fields = append(fields, fmt.Sprintf("unit=0x%x", this.Unit))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_SigInfo struct {
    Index uint8
    Len   uint32
    config.SigInfo
}

func (this *Arg_SigInfo) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("si_signo=0x%x", this.Si_signo))
    fields = append(fields, fmt.Sprintf("si_errno=0x%x", this.Si_errno))
    fields = append(fields, fmt.Sprintf("si_code=0x%x", this.Si_code))
    // fields = append(fields, fmt.Sprintf("sifields=0x%x", this.Sifields))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Msghdr struct {
    Index uint8
    Len   uint32
    config.Msghdr
}

func (this *Arg_Msghdr) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("name=0x%x", this.Name))
    fields = append(fields, fmt.Sprintf("namelen=0x%x", this.Namelen))
    fields = append(fields, fmt.Sprintf("iov=0x%x", this.Iov))
    fields = append(fields, fmt.Sprintf("iovlen=0x%x", this.Iovlen))
    fields = append(fields, fmt.Sprintf("control=0x%x", this.Control))
    fields = append(fields, fmt.Sprintf("controllen=0x%x", this.Controllen))
    fields = append(fields, fmt.Sprintf("flags=0x%x", this.Flags))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_ItTmerspec struct {
    Index uint8
    Len   uint32
    config.ItTmerspec
}

func (this *Arg_ItTmerspec) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("it_interval={sec=%d, nsec=%d}", this.It_interval.Sec, this.It_interval.Nsec))
    fields = append(fields, fmt.Sprintf("it_value={sec=%d, nsec=%d}", this.It_value.Sec, this.It_value.Nsec))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Stack_t struct {
    Index uint8
    Len   uint32
    config.Stack_t
}

func (this *Arg_Stack_t) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("ss_sp=0x%x", this.Ss_sp))
    fields = append(fields, fmt.Sprintf("ss_flags=%d", this.Ss_flags))
    fields = append(fields, fmt.Sprintf("ss_size=%d", this.Ss_size))
    return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

func B2S(bs []int8) string {
    ba := make([]byte, 0, len(bs))
    for _, b := range bs {
        ba = append(ba, byte(b))
    }
    return util.B2STrim(ba)
}

func I2B(bs []int8) []byte {
    ba := make([]byte, 0, len(bs))
    for _, b := range bs {
        ba = append(ba, byte(b))
    }
    return ba
}

type Arg_bytes = Arg_str

func (this *SyscallEvent) ParseContextSysEnter() (err error) {
    if err = binary.Read(this.buf, binary.LittleEndian, &this.lr); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pc); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.sp); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
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
        // this.logger.Printf(".... AliasType:%d %d %d", point_arg.AliasType, this.EventId, point_arg.ReadFlag)
        var ptr Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        base_arg_str := fmt.Sprintf("%s=0x%x", point_arg.ArgName, ptr.Address)
        point_arg.SetValue(base_arg_str)
        if point_arg.Type == config.TYPE_NUM {
            // 目前会全部输出为 hex 后续优化改进
            results = append(results, point_arg.ArgValue)
            continue
        }
        // 这一类参数要等执行结束后读取 这里只获取参数所对应的寄存器值就可以了
        if point_arg.ReadFlag == config.SYS_EXIT {
            results = append(results, point_arg.ArgValue)
            continue
        }
        this.ParseArgByType(&point_arg, ptr)
        results = append(results, point_arg.ArgValue)
    }
    // if !this.WaitExit {
    //     var results []string
    //     for _, point_arg := range this.nr_point.Args {
    //         results = append(results, point_arg.ArgValue)
    //     }
    //     this.arg_str = "(" + strings.Join(results, ", ") + ")"
    // }
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
        var ptr Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            this.logger.Printf("SyscallEvent EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
            panic(fmt.Sprintf("binary.Read %d %s err:%v", this.nr.Value, util.B2STrim(this.Comm[:]), err))
        }
        base_arg_str := fmt.Sprintf("%s=0x%x", point_arg.ArgName, ptr.Address)
        point_arg.SetValue(base_arg_str)
        if point_arg.Type == config.TYPE_NUM {
            results = append(results, point_arg.ArgValue)
            continue
        }
        if point_arg.ReadFlag != config.SYS_EXIT {
            results = append(results, point_arg.ArgValue)
            continue
        }
        this.ParseArgByType(&point_arg, ptr)
        results = append(results, point_arg.ArgValue)
    }
    // 处理返回参数
    var ptr Arg_reg
    if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    point_arg := this.nr_point.Ret
    base_arg_str := fmt.Sprintf("0x%x", ptr.Address)
    point_arg.SetValue(base_arg_str)
    if point_arg.Type != config.TYPE_NUM {
        this.ParseArgByType(&point_arg, ptr)
    }
    if len(results) == 0 {
        results = append(results, "(void)")
    }
    this.arg_str = fmt.Sprintf("(%s => %s)", point_arg.ArgValue, strings.Join(results, ", "))
    return nil
}

func (this *SyscallEvent) WaitNextEvent() bool {
    return this.WaitExit
}

// func (this *SyscallEvent) MergeEvent(exit_event IEventStruct) {
//     exit_p, ok := (exit_event).(*SyscallEvent)
//     if !ok {
//         panic("cast event.SYSCALL_EXIT to event.SyscallEvent failed")
//     }
//     var results []string
//     for index, point_arg := range this.nr_point.Args {
//         if point_arg.ReadFlag == config.SYS_EXIT {
//             point_arg = exit_p.nr_point.Args[index]
//         }
//         results = append(results, point_arg.ArgValue)
//     }
//     results = append(results, exit_p.nr_point.Ret.ArgValue)
//     this.arg_str = "(" + strings.Join(results, ", ") + ")"
//     this.WaitExit = false
// }

func (this *SyscallEvent) ParseContext() (err error) {
    this.WaitExit = false
    // this.logger.Printf("SyscallEvent EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
    // 处理参数 常规参数的构成 是 索引 + 值
    if err = binary.Read(this.buf, binary.LittleEndian, &this.nr); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if this.EventId == SYSCALL_ENTER {
        // 是否有不执行 sys_exit 的情况 ?
        // 有的调用耗时 也有可能 要不还是把执行结果分开输出吧
        // this.WaitExit = true
        this.ParseContextSysEnter()
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
    return fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
}

func (this *SyscallEvent) String() string {
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
    base_str = this.GetStackTrace(base_str)
    return base_str
}

func (this *SyscallEvent) ParseLRV1() (string, error) {
    return maps_helper.GetOffset(this.Pid, this.lr.Address), nil
}

func (this *SyscallEvent) Clone() IEventStruct {
    event := new(SyscallEvent)
    return event
}
