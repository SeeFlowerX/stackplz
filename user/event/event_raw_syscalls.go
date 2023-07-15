package event

import (
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "stackplz/pkg/util"
    "strings"
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
    event_type    EventType
    UUID          string
    Stackinfo     string
    RegsBuffer    RegsBuf
    UnwindBuffer  UnwindBuf
    nr            Arg_nr
    lr            Arg_reg
    sp            Arg_reg
    pc            Arg_reg
    ret           uint64
    arg_index     uint64
    args          [6]uint64
    arg_str       [512]byte
    arg_enter_str string
}

type Arg_nr struct {
    Index uint8
    Value int32
}
type Arg_reg struct {
    Index   uint8
    Address uint64
}
type Arg_str struct {
    Index uint8
    Len   uint32
}

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

const (
    TYPE_POINTER uint32 = iota
    TYPE_NUM
    TYPE_STRING
    TYPE_STRUCT
)

func (this *SyscallEvent) ParseContext() (err error) {
    // this.logger.Printf("SyscallEvent.ParseContext() RawSample:\n" + util.HexDump(this.rec.RawSample, util.COLORRED))
    // 处理参数 常规参数的构成 是 索引 + 值
    if err = binary.Read(this.buf, binary.LittleEndian, &this.nr); err != nil {
        return
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.lr); err != nil {
        return
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pc); err != nil {
        return
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.sp); err != nil {
        return
    }
    // 根据调用号解析剩余参数
    nr := this.mconf.SysCallConf.SysTable.ReadNRConfig(uint32(this.nr.Value))
    // switch nr.Name {
    // case "openat":
    //     {

    //     }
    // }
    var args []string
    var arg Arg_reg
    left_argnum := uint32(this.argnum - 4)
    arg_index := 0
    arg_type := TYPE_POINTER
    for i := 0; i < int(left_argnum); i++ {
        if arg_index >= int(nr.Count) {
            // 后续优化到 ebpf 中过滤，减少浪费
            break
        }
        switch arg_type {
        case TYPE_POINTER:
            if err = binary.Read(this.buf, binary.LittleEndian, &arg); err != nil {
                break
            }
            args = append(args, fmt.Sprintf("0x%x", arg.Address))
            if nr.Mask&(1<<arg_index) != 0 {
                arg_type = TYPE_STRING
            }
            arg_index += 1
            break
        case TYPE_NUM:
            if err = binary.Read(this.buf, binary.LittleEndian, &arg); err != nil {
                break
            }
            args = append(args, fmt.Sprintf("0x%x", arg.Address))
            arg_index += 1
            break
        case TYPE_STRING:
            var arg_str Arg_str
            if err = binary.Read(this.buf, binary.LittleEndian, &arg_str); err != nil {
                break
            }
            payload := make([]byte, arg_str.Len)
            if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
                break
            }
            args = append(args, util.B2STrim(payload))
            arg_type = TYPE_POINTER
            break
        default:
            panic(fmt.Sprintf("unknown arg_type %d", arg_type))
        }
    }
    this.arg_enter_str = strings.Join(args, ", ")
    return nil
}

func (this *SyscallEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.pid, this.tid, util.B2STrim(this.comm[:]))
}

func (this *SyscallEvent) String() string {
    nr := this.mconf.SysCallConf.SysTable.ReadNR(uint32(this.nr.Value))
    var base_str string
    base_str = fmt.Sprintf("[%s] nr:%s %s", this.GetUUID(), nr, this.arg_enter_str)
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

func (this *SyscallEvent) ReadArgs() string {
    config := this.mconf.SysCallConf.SysTable[fmt.Sprintf("%d", this.nr.Value)]
    regs := make(map[string]string)
    for i := 0; i < int(config.Count); i++ {
        regs[fmt.Sprintf("x%d", i)] = fmt.Sprintf("0x%x", this.args[i])
    }
    regs["lr"] = fmt.Sprintf("0x%x", this.lr)
    regs["sp"] = fmt.Sprintf("0x%x", this.sp)
    regs["pc"] = fmt.Sprintf("0x%x", this.pc)
    regs_info, err := json.Marshal(regs)
    if err != nil {
        regs_info = make([]byte, 0)
    }
    return string(regs_info)
}

func (this *SyscallEvent) EventType() EventType {
    return this.event_type
}

func (this *SyscallEvent) Clone() IEventStruct {
    event := new(SyscallEvent)
    event.event_type = EventTypeSysCallData
    return event
}
