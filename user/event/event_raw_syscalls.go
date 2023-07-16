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
    Etype        uint32
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
type Arg_Timespec struct {
    Index uint8
    Len   uint32
    syscall.Timespec
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

func (this *SyscallEvent) ParseContext() (err error) {
    // this.logger.Printf("SyscallEvent eventid:%d RawSample:\n%s", this.eventid, util.HexDump(this.rec.RawSample, util.COLORRED))
    // 处理参数 常规参数的构成 是 索引 + 值
    if err = binary.Read(this.buf, binary.LittleEndian, &this.nr); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if this.eventid == SYSCALL_ENTER {
        if err = binary.Read(this.buf, binary.LittleEndian, &this.lr); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        if err = binary.Read(this.buf, binary.LittleEndian, &this.pc); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        if err = binary.Read(this.buf, binary.LittleEndian, &this.sp); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
    }
    // 根据调用号解析剩余参数
    // nr := this.mconf.SysCallConf.SysTable.ReadNRConfig(uint32(this.nr.Value))
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
        if point_arg.Type == config.TYPE_NUM {
            results = append(results, base_arg_str)
            continue
        }
        if this.eventid == SYSCALL_ENTER && point_arg.ReadFlag == config.SYS_EXIT {
            results = append(results, base_arg_str)
            continue
        }
        if this.eventid == SYSCALL_EXIT && point_arg.ReadFlag == config.SYS_ENTER {
            results = append(results, base_arg_str)
            continue
        }
        switch point_arg.AliasType {
        case config.TYPE_NUM:
            break
        case config.TYPE_STRING:
            var arg_str Arg_str
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_str); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            payload := make([]byte, arg_str.Len)
            if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            results = append(results, fmt.Sprintf("%s(%s)", base_arg_str, util.B2STrim(payload)))
        case config.TYPE_POINTER:
            // 先解析参数寄存器本身的值
            var ptr_value Arg_reg
            // 再解析参数寄存器指向地址的值
            if err = binary.Read(this.buf, binary.LittleEndian, &ptr_value); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            results = append(results, fmt.Sprintf("%s(0x%x)", base_arg_str, ptr_value.Address))
        case config.TYPE_STRUCT:
            payload := make([]byte, point_arg.Size)
            if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            results = append(results, fmt.Sprintf("%s([hex]%x)", base_arg_str, payload))
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
            results = append(results, fmt.Sprintf("%s(%s)", base_arg_str, time_fmt))
        case config.TYPE_SOCKADDR:
            var sockaddr syscall.RawSockaddrAny
            if err = binary.Read(this.buf, binary.LittleEndian, &sockaddr); err != nil {
                panic(fmt.Sprintf("binary.Read err:%v", err))
            }
            results = append(results, fmt.Sprintf("%s={family: %d, data: [hex]%x, pad: [hex]%x}", point_arg.ArgName, sockaddr.Addr.Family, sockaddr.Addr.Data, sockaddr.Pad))
        default:
            panic(fmt.Sprintf("unknown point_arg.AliasType %d", point_arg.AliasType))
        }
    }
    this.arg_str = "(" + strings.Join(results, ", ") + ")"
    if this.eventid == SYSCALL_EXIT {
        var ptr Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        this.arg_str = fmt.Sprintf("[ret=0x%x]", ptr.Address) + this.arg_str
    }
    return nil
}

func (this *SyscallEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.pid, this.tid, util.B2STrim(this.comm[:]))
}

func (this *SyscallEvent) String() string {
    var base_str string
    base_str = fmt.Sprintf("[%s] nr:%s%s", this.GetUUID(), this.nr_point.PointName, this.arg_str)
    base_str = fmt.Sprintf("%s LR:0x%x PC:0x%x SP:0x%x", base_str, this.lr.Address, this.pc.Address, this.sp.Address)
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
    return maps_helper.GetOffset(this.event_context.Pid, this.lr.Address), nil
}

func (this *SyscallEvent) ParseLR() (string, error) {
    info := "UNKNOWN"
    // 直接读取maps信息 计算lr在什么地方 定位syscall调用也就一目了然了
    filename := fmt.Sprintf("/proc/%d/maps", this.event_context.Pid)
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
    return maps_helper.GetOffset(this.event_context.Pid, this.pc.Address), nil
}

func (this *SyscallEvent) ParsePC() (string, error) {
    info := "UNKNOWN"
    // 直接读取maps信息 计算pc在什么地方 定位syscall调用也就一目了然了
    filename := fmt.Sprintf("/proc/%d/maps", this.event_context.Pid)
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
