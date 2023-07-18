package event

import (
    "encoding/binary"
    "errors"
    "fmt"
    "io/ioutil"
    "stackplz/pkg/util"
    "stackplz/user/config"
    "strings"
    "syscall"
    "time"
)

// type EventTypeSys uint32

const (
    EventTypeSysEnter             uint32 = 1
    EventTypeSysEnterArgs         uint32 = 2
    EventTypeSysEnterRegs         uint32 = 3
    EventTypeSysExitReadAfterArgs uint32 = 4
    EventTypeSysExitArgs          uint32 = 5
    EventTypeSysExitRet           uint32 = 6
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
    event_type   EventType
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
type Arg_reg struct {
    Index   uint8
    Address uint64
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
    return fmt.Sprintf("stat{%s}", strings.Join(fields, ", "))
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
    return fmt.Sprintf("statfs{%s}", strings.Join(fields, ", "))
}

func (this *Arg_Sigaction) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("sa_handler=0x%x", this.Sa_handler))
    fields = append(fields, fmt.Sprintf("sa_sigaction=0x%x", this.Sa_sigaction))
    fields = append(fields, fmt.Sprintf("sa_mask=0x%x", this.Sa_mask))
    fields = append(fields, fmt.Sprintf("sa_flags=0x%x", this.Sa_flags))
    fields = append(fields, fmt.Sprintf("sa_restorer=0x%x", this.Sa_restorer))
    return fmt.Sprintf("sigaction{%s}", strings.Join(fields, ", "))
}

type Arg_Utsname struct {
    Index uint8
    Len   uint32
    syscall.Utsname
}
type Arg_Iovec struct {
    Index  uint8
    Len    uint32
    Base   uint64
    BufLen uint64
    // syscall.Iovec
}

func (this *Arg_Iovec) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("base=0x%x", this.Base))
    fields = append(fields, fmt.Sprintf("len=0x%x", this.BufLen))
    return fmt.Sprintf("iovec{%s}", strings.Join(fields, ", "))
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
    return fmt.Sprintf("epollevent{%s}", strings.Join(fields, ", "))
}

type Arg_Rusage struct {
    Index uint8
    Len   uint32
    syscall.Rusage
}

func (this *Arg_Rusage) Format() string {
    var fields []string
    fields = append(fields, fmt.Sprintf("utime=timeval{sec=%d, sec=%d}", this.Utime.Sec, this.Utime.Usec))
    fields = append(fields, fmt.Sprintf("stime=timeval{sec=%d, sec=%d}", this.Stime.Sec, this.Stime.Usec))
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
    return fmt.Sprintf("rusage{%s}", strings.Join(fields, ", "))
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
    return fmt.Sprintf("rusage{%s}", strings.Join(fields, ", "))
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
    return fmt.Sprintf("rusage{%s}", strings.Join(fields, ", "))
}

func B2S(bs []int8) string {
    ba := make([]byte, 0, len(bs))
    for _, b := range bs {
        ba = append(ba, byte(b))
    }
    return util.B2STrim(ba)
}

type Arg_bytes = Arg_str

func (this *SyscallEvent) Decode() (err error) {
    return nil
}

func (this *SyscallEvent) ReadIndex() (error, uint32) {
    var index uint8 = 0
    if err := binary.Read(this.buf, binary.LittleEndian, &index); err != nil {
        return errors.New(fmt.Sprintf("SyscallEvent.ReadIndex() failed, err:%v", err)), uint32(index)
    }
    return nil, uint32(index)
}

func (this *SyscallEvent) ParseArg(point_arg *config.PointArg, ptr Arg_reg) (err error) {
    switch point_arg.AliasType {
    case config.TYPE_NONE:
        break
    case config.TYPE_NUM:
        break
    case config.TYPE_STRING:
        var arg_str Arg_str
        if err = binary.Read(this.buf, binary.LittleEndian, &arg_str); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        payload := make([]byte, arg_str.Len)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            this.logger.Printf("SyscallEvent eventid:%d RawSample:\n%s", this.eventid, util.HexDump(this.rec.RawSample, util.COLORGREEN))
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", util.B2STrim(payload)))
    case config.TYPE_STRING_ARR:
        var arg_str_arr Arg_str_arr
        if err = binary.Read(this.buf, binary.LittleEndian, &arg_str_arr); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        var str_arr []string
        for i := 0; i < int(arg_str_arr.Count); i++ {
            var len uint32
            if err = binary.Read(this.buf, binary.LittleEndian, &len); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            payload := make([]byte, len)
            if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            str_arr = append(str_arr, util.B2STrim(payload))
        }
        point_arg.AppendValue(fmt.Sprintf("[%s]", strings.Join(str_arr, ", ")))
    case config.TYPE_POINTER:
        // 先解析参数寄存器本身的值
        var ptr_value Arg_reg
        // 再解析参数寄存器指向地址的值
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr_value); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        point_arg.AppendValue(fmt.Sprintf("(0x%x)", ptr_value.Address))
    case config.TYPE_SIGSET:
        var sigs [8]uint32
        if err = binary.Read(this.buf, binary.LittleEndian, &sigs); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        var fmt_sigs []string
        for i := 0; i < len(sigs); i++ {
            fmt_sigs = append(fmt_sigs, fmt.Sprintf("0x%x", sigs[i]))
        }
        point_arg.AppendValue(fmt.Sprintf("(sigs=[%s])", strings.Join(fmt_sigs, ",")))
    case config.TYPE_POLLFD:
        var pollfd Arg_Pollfd
        if err = binary.Read(this.buf, binary.LittleEndian, &pollfd); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        point_arg.AppendValue(fmt.Sprintf("(fd=%d, events=%d, revents=%d)", pollfd.Fd, pollfd.Events, pollfd.Revents))
    case config.TYPE_STRUCT:
        payload := make([]byte, point_arg.Size)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        point_arg.AppendValue(fmt.Sprintf("([hex]%x)", payload))
    case config.TYPE_TIMESPEC:
        var time_fmt string
        if ptr.Address != 0 {
            var arg_time Arg_Timespec
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_time); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            time_fmt = fmt.Sprintf("timespec{tv_sec=%d, tv_nsec=%d}", arg_time.Sec, arg_time.Nsec)
        } else {
            time_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", time_fmt))
    case config.TYPE_STAT:
        var stat_fmt string
        if ptr.Address != 0 {
            var arg_stat_t Arg_Stat_t
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_stat_t); err != nil {
                this.logger.Printf("SyscallEvent eventid:%d RawSample:\n%s", this.eventid, util.HexDump(this.rec.RawSample, util.COLORRED))
                time.Sleep(3 * 1000 * time.Millisecond)
                panic(fmt.Sprintf("binary.Read %d %s err:%v", this.nr.Value, util.B2STrim(this.comm[:]), err))
            }
            stat_fmt = arg_stat_t.Format()
        } else {
            stat_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", stat_fmt))
    case config.TYPE_STATFS:
        var statfs_fmt string
        if ptr.Address != 0 {
            var arg_statfs_t Arg_Statfs_t
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_statfs_t); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            statfs_fmt = arg_statfs_t.Format()
        } else {
            statfs_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", statfs_fmt))
    case config.TYPE_SIGACTION:
        var fmt_str string
        if ptr.Address != 0 {
            var arg_sigaction Arg_Sigaction
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_sigaction); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            fmt_str = arg_sigaction.Format()
        } else {
            fmt_str = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", fmt_str))
    case config.TYPE_UTSNAME:
        var name_fmt string
        if ptr.Address != 0 {
            var arg_name Arg_Utsname
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_name); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            sysname := B2S(arg_name.Sysname[:])
            nodename := B2S(arg_name.Nodename[:])
            release := B2S(arg_name.Release[:])
            version := B2S(arg_name.Version[:])
            machine := B2S(arg_name.Machine[:])
            domainname := B2S(arg_name.Domainname[:])
            name_fmt = fmt.Sprintf("utsname{sysname=%s, nodename=%s, release=%s, version=%s, machine=%s, domainname=%s}", sysname, nodename, release, version, machine, domainname)
        } else {
            name_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", name_fmt))
    case config.TYPE_SOCKADDR:
        var sockaddr syscall.RawSockaddrAny
        if err = binary.Read(this.buf, binary.LittleEndian, &sockaddr); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        point_arg.AppendValue(fmt.Sprintf("({family: %d, data: [hex]%x, pad: [hex]%x})", sockaddr.Addr.Family, sockaddr.Addr.Data, sockaddr.Pad))
    case config.TYPE_RUSAGE:
        var arg_fmt string
        if ptr.Address != 0 {
            var arg_rusage Arg_Rusage
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_rusage); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            arg_fmt = arg_rusage.Format()
        } else {
            arg_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", arg_fmt))
    case config.TYPE_IOVEC:
        var arg_fmt string
        if ptr.Address != 0 {
            var arg_iovec Arg_Iovec
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_iovec); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            arg_fmt = arg_iovec.Format()
        } else {
            arg_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", arg_fmt))
    case config.TYPE_EPOLLEVENT:
        var arg_fmt string
        if ptr.Address != 0 {
            var arg_epollevent Arg_EpollEvent
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_epollevent); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            arg_fmt = arg_epollevent.Format()
        } else {
            arg_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", arg_fmt))
    case config.TYPE_SYSINFO:
        var arg_fmt string
        if ptr.Address != 0 {
            var arg Arg_Sysinfo_t
            if err = binary.Read(this.buf, binary.LittleEndian, &arg); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            arg_fmt = arg.Format()
        } else {
            arg_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", arg_fmt))
    case config.TYPE_SIGINFO:
        // 这个读取出来有问题
        var arg_fmt string
        if ptr.Address != 0 {
            var arg Arg_SigInfo
            if err = binary.Read(this.buf, binary.LittleEndian, &arg); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            arg_fmt = arg.Format()
        } else {
            arg_fmt = "NULL"
        }
        point_arg.AppendValue(fmt.Sprintf("(%s)", arg_fmt))
    default:
        panic(fmt.Sprintf("unknown point_arg.AliasType %d", point_arg.AliasType))
    }
    return nil
}

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
        // this.logger.Printf(".... AliasType:%d %d %d", point_arg.AliasType, this.eventid, point_arg.ReadFlag)
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
        this.ParseArg(&point_arg, ptr)
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
            this.logger.Printf("SyscallEvent eventid:%d RawSample:\n%s", this.eventid, util.HexDump(this.rec.RawSample, util.COLORRED))
            panic(fmt.Sprintf("binary.Read %d %s err:%v", this.nr.Value, util.B2STrim(this.comm[:]), err))
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
        this.ParseArg(&point_arg, ptr)
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
        this.ParseArg(&point_arg, ptr)
    }
    this.arg_str = "(" + point_arg.ArgValue + " => " + strings.Join(results, ", ") + ")"
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
    // this.logger.Printf("SyscallEvent eventid:%d RawSample:\n%s", this.eventid, util.HexDump(this.rec.RawSample, util.COLORRED))
    // 处理参数 常规参数的构成 是 索引 + 值
    if err = binary.Read(this.buf, binary.LittleEndian, &this.nr); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if this.eventid == SYSCALL_ENTER {
        // 是否有不执行 sys_exit 的情况 ?
        // 有的调用耗时 也有可能 要不还是把执行结果分开输出吧
        // this.WaitExit = true
        this.ParseContextSysEnter()
    } else if this.eventid == SYSCALL_EXIT {
        this.ParseContextSysExit()
    } else {
        panic(fmt.Sprintf("SyscallEvent.ParseContext() failed, eventid:%d", this.eventid))
    }

    return nil
}

func (this *SyscallEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.pid, this.tid, util.B2STrim(this.comm[:]))
}

func (this *SyscallEvent) String() string {
    var base_str string
    base_str = fmt.Sprintf("[%s] nr:%s%s", this.GetUUID(), this.nr_point.PointName, this.arg_str)
    if this.eventid == SYSCALL_ENTER {
        base_str = fmt.Sprintf("%s LR:0x%x PC:0x%x SP:0x%x", base_str, this.lr.Address, this.pc.Address, this.sp.Address)
    }
    // type 和数据发送的顺序相关
    // switch this.mtype {
    // case EventTypeSysEnter:
    //     // --getlr 和 --getpc 建议只使用其中一个
    //     if conf.GetLR {
    //         // info, err := this.ParseLR()
    //         info, err := this.ParseLRV1()
    //         if err != nil {
    //             return fmt.Sprintf("ParseLR err:%v\n", err)
    //         }
    //         return fmt.Sprintf("%s LR:0x%x Info:\n%s\n", base_str, this.lr, info)
    //     }
    //     if conf.GetPC {
    //         // info, err := this.ParsePC()
    //         info, err := this.ParsePCV1()
    //         if err != nil {
    //             return fmt.Sprintf("ParsePC err:%v\n", err)
    //         }
    //         return fmt.Sprintf("%s PC:0x%x Info:\n%s\n", base_str, this.pc, info)
    //     }
    // case EventTypeSysEnterArgs:
    //     var arg_str string
    //     if nr == "nanosleep" {
    //         var spec Timespec
    //         t_buf := bytes.NewBuffer(this.arg_str[:])
    //         if err := binary.Read(t_buf, binary.LittleEndian, &spec); err != nil {
    //             return fmt.Sprintf("%s", err)
    //         }
    //         arg_str = spec.String()
    //     } else {
    //         arg_str = strings.SplitN(string(bytes.Trim(this.arg_str[:], "\x00")), "\x00", 2)[0]
    //     }
    //     return fmt.Sprintf("%s arg_%d arg_str:%s", base_str, this.arg_index, strings.TrimSpace(arg_str))
    // case EventTypeSysEnterRegs:
    //     return fmt.Sprintf("%s %s", base_str, this.ReadArgs())
    // case EventTypeSysExitReadAfterArgs:
    //     arg_str := strings.SplitN(string(bytes.Trim(this.arg_str[:], "\x00")), "\x00", 2)[0]
    //     return fmt.Sprintf("%s arg_%d arg_after_str:%s", base_str, this.arg_index, strings.TrimSpace(arg_str))
    // case EventTypeSysExitArgs:
    //     arg_str := strings.SplitN(string(bytes.Trim(this.arg_str[:], "\x00")), "\x00", 2)[0]
    //     return fmt.Sprintf("%s arg_%d arg_ret_str:%s", base_str, this.arg_index, strings.TrimSpace(arg_str))
    // case EventTypeSysExitRet:
    //     return fmt.Sprintf("%s ret:0x%x", base_str, this.ret)
    // }
    // this.logger.Printf("SyscallEvent.String() base_str:" + base_str)
    return base_str
}

func (this *SyscallEvent) ParseLRV1() (string, error) {
    return maps_helper.GetOffset(this.pid, this.lr.Address), nil
}

func (this *SyscallEvent) ParseLR() (string, error) {
    info := "UNKNOWN"
    // 直接读取maps信息 计算lr在什么地方 定位syscall调用也就一目了然了
    filename := fmt.Sprintf("/proc/%d/maps", this.pid)
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        return info, fmt.Errorf("Error when opening file:%v", err)
    }
    var (
        seg_start  uint64
        seg_end    uint64
        permission string
        seg_offset uint64
        device     string
        inode      uint64
        seg_path   string
    )
    for _, line := range strings.Split(string(content), "\n") {
        reader := strings.NewReader(line)
        n, err := fmt.Fscanf(reader, "%x-%x %s %x %s %d %s", &seg_start, &seg_end, &permission, &seg_offset, &device, &inode, &seg_path)
        if err == nil && n == 7 {
            if this.lr.Address >= seg_start && this.lr.Address < seg_end {
                offset := seg_offset + (this.lr.Address - seg_start)
                info = fmt.Sprintf("%s + 0x%x", seg_path, offset)
                break
            }
        }
    }
    return info, err
}

func (this *SyscallEvent) ParsePCV1() (string, error) {
    // 通过在启动阶段收集到的库基址信息来计算偏移
    // 由于每个进程的加载情况不一样 这里要传递 pid
    return maps_helper.GetOffset(this.pid, this.pc.Address), nil
}

func (this *SyscallEvent) ParsePC() (string, error) {
    info := "UNKNOWN"
    // 直接读取maps信息 计算pc在什么地方 定位syscall调用也就一目了然了
    filename := fmt.Sprintf("/proc/%d/maps", this.pid)
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        return info, fmt.Errorf("Error when opening file:%v", err)
    }
    var (
        seg_start  uint64
        seg_end    uint64
        permission string
        seg_offset uint64
        device     string
        inode      uint64
        seg_path   string
    )
    for _, line := range strings.Split(string(content), "\n") {
        reader := strings.NewReader(line)
        n, err := fmt.Fscanf(reader, "%x-%x %s %x %s %d %s", &seg_start, &seg_end, &permission, &seg_offset, &device, &inode, &seg_path)
        if err == nil && n == 7 {
            if this.pc.Address >= seg_start && this.pc.Address < seg_end {
                offset := seg_offset + (this.pc.Address - seg_start)
                info = fmt.Sprintf("%s + 0x%x", seg_path, offset)
                break
            }
        }
    }
    return info, err
}

// func (this *SyscallEvent) ReadArgs() string {
//     config := this.mconf.SysCallConf.SysTable[fmt.Sprintf("%d", this.nr.Value)]
//     regs := make(map[string]string)
//     for i := 0; i < int(config.Count); i++ {
//         regs[fmt.Sprintf("x%d", i)] = fmt.Sprintf("0x%x", this.args[i])
//     }
//     regs["lr"] = fmt.Sprintf("0x%x", this.lr)
//     regs["sp"] = fmt.Sprintf("0x%x", this.sp)
//     regs["pc"] = fmt.Sprintf("0x%x", this.pc)
//     regs_info, err := json.Marshal(regs)
//     if err != nil {
//         regs_info = make([]byte, 0)
//     }
//     return string(regs_info)
// }

func (this *SyscallEvent) EventType() EventType {
    return this.event_type
}

func (this *SyscallEvent) Clone() IEventStruct {
    event := new(SyscallEvent)
    event.event_type = EventTypeSysCallData
    return event
}
