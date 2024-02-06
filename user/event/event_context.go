package event

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "stackplz/user/common"
    "stackplz/user/config"
    "stackplz/user/util"
    "strings"
    "syscall"

    "golang.org/x/sys/unix"
)

const (
    PERF_SAMPLE_REGS_ABI_NONE uint64 = iota
    PERF_SAMPLE_REGS_ABI_32
    PERF_SAMPLE_REGS_ABI_64
)

func ReadRegs(abi uint64, buf *bytes.Buffer) []uint64 {
    switch abi {
    case PERF_SAMPLE_REGS_ABI_32:
        regs := make([]uint64, common.REG_ARM_MAX)
        if err := binary.Read(buf, binary.LittleEndian, &regs); err != nil {
            panic(err)
        }
        return regs
    case PERF_SAMPLE_REGS_ABI_64:
        regs := make([]uint64, common.REG_ARM64_MAX)
        if err := binary.Read(buf, binary.LittleEndian, &regs); err != nil {
            panic(err)
        }
        return regs
    default:
        panic(fmt.Sprintf("abi %d not support", abi))
    }
}

type UnwindOption struct {
    Abi       uint64
    StackSize uint64
    DynSize   uint64
    RegMask   uint64
    ShowPC    bool
}

type UnwindBuf struct {
    Abi       uint64
    Regs      []uint64
    StackSize uint64
    Data      []byte
    DynSize   uint64
}

func (this *UnwindBuf) ParseContext(buf *bytes.Buffer) (err error) {
    if err = binary.Read(buf, binary.LittleEndian, &this.Abi); err != nil {
        return err
    }
    this.Regs = ReadRegs(this.Abi, buf)
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
    Regs []uint64
}

func (this *RegsBuf) ParseContext(buf *bytes.Buffer) (err error) {
    if err = binary.Read(buf, binary.LittleEndian, &this.Abi); err != nil {
        return err
    }
    this.Regs = ReadRegs(this.Abi, buf)
    return nil
}

type ContextEvent struct {
    CommonEvent
    config.ContextFields
    Stackinfo    string
    RegsBuffer   RegsBuf
    UnwindBuffer *UnwindBuf
}

func (this *ContextEvent) GetOffset(addr uint64) string {
    return maps_helper.GetOffset(this.Pid, addr)
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

func (this *ContextEvent) ParseEvent() (IEventStruct, error) {
    switch this.rec.RecordType {
    case unix.PERF_RECORD_SAMPLE:
        // 先把需要的基础信息解析出来
        err := this.ParseContext()
        if err != nil {
            panic(fmt.Sprintf("ContextEvent.ParseContext() err:%v", err))
        }

        EventId := this.GetEventId()
        switch EventId {
        case SYSCALL_ENTER, SYSCALL_EXIT:
            return nil, nil
        case UPROBE_ENTER:
            return nil, nil
        default:
            this.logger.Printf("ContextEvent.ParseEvent() unsupported EventId:%d\n", EventId)
            this.logger.Printf("ContextEvent.ParseEvent() PERF_RECORD_SAMPLE RawSample:\n" + util.HexDump(this.rec.RawSample, util.COLORRED))
            return nil, errors.New(fmt.Sprintf("PERF_RECORD_SAMPLE EventId is %d", EventId))
        }
    default:
        return this.CommonEvent.ParseEvent()
    }

}

func (this *ContextEvent) ParseContext() (err error) {
    if this.mconf.BrkKernel {
        return nil
    }
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
    if this.mconf.KillSignal == uint32(syscall.SIGSTOP) && this.Pid != 0 {
        AddStopped(this.Pid)
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

func (this *ContextEvent) GetRegsString() string {
    result := []string{}
    if this.mconf.Is32Bit {
        if this.rec.ExtraOptions.UnwindStack {
            for reg_index, reg_value := range this.UnwindBuffer.Regs {
                result = append(result, fmt.Sprintf("%s=0x%x", common.RegsArmIdxMap[uint32(reg_index)], reg_value))
            }
        } else {
            for reg_index, reg_value := range this.RegsBuffer.Regs {
                result = append(result, fmt.Sprintf("%s=0x%x", common.RegsArmIdxMap[uint32(reg_index)], reg_value))
            }
        }
    } else {
        if this.rec.ExtraOptions.UnwindStack {
            for reg_index, reg_value := range this.UnwindBuffer.Regs {
                result = append(result, fmt.Sprintf("%s=0x%x", common.RegsIdxMap[uint32(reg_index)], reg_value))
            }
        } else {
            for reg_index, reg_value := range this.RegsBuffer.Regs {
                result = append(result, fmt.Sprintf("%s=0x%x", common.RegsIdxMap[uint32(reg_index)], reg_value))
            }
        }
    }
    return "[" + strings.Join(result, ",") + "]"
}

func (this *ContextEvent) GetRegValue(reg_name string) uint64 {
    if this.mconf.Is32Bit {
        if this.rec.ExtraOptions.UnwindStack {
            return this.UnwindBuffer.Regs[common.RegsArmNameMap[reg_name]]
        } else {
            return this.RegsBuffer.Regs[common.RegsArmNameMap[reg_name]]
        }
    } else {
        if this.rec.ExtraOptions.UnwindStack {
            return this.UnwindBuffer.Regs[common.RegsNameMap[reg_name]]
        } else {
            return this.RegsBuffer.Regs[common.RegsNameMap[reg_name]]
        }
    }
}

func (this *ContextEvent) GetStackTrace(s string) string {
    if this.mconf.RegName != "" {
        reg_info := []string{}
        for _, reg_name := range strings.Split(this.mconf.RegName, ",") {
            reg_value := this.GetRegValue(reg_name)
            info, err := util.ParseReg(this.Pid, reg_value)
            if err != nil {
                fmt.Printf("ParseReg for %s=0x%x failed", reg_name, reg_value)
            } else {
                reg_info = append(reg_info, fmt.Sprintf("%s(0x%x %s)", reg_name, reg_value, info))
            }
        }
        s += fmt.Sprintf(", RegsInfo:\n%s", strings.Join(reg_info, "\n"))
    }
    if this.mconf.ShowRegs {
        s += ", Regs:\n" + this.GetRegsString()
    }
    if this.Stackinfo != "" {
        if this.mconf.ShowRegs {
            s += fmt.Sprintf("\nBacktrace:\n%s", this.Stackinfo)
        } else {
            s += fmt.Sprintf(", Backtrace:\n%s", this.Stackinfo)
        }
    }
    return s
}

func (this *ContextEvent) GetOpt() *UnwindOption {
    opt := &UnwindOption{}
    opt.RegMask = (1 << common.REG_ARM64_MAX) - 1
    if this.mconf.Is32Bit {
        opt.RegMask = (1 << common.REG_ARM_MAX) - 1
    }
    opt.ShowPC = this.mconf.ShowPC
    opt.Abi = this.UnwindBuffer.Abi
    opt.StackSize = this.UnwindBuffer.StackSize
    opt.DynSize = this.UnwindBuffer.DynSize
    return opt
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
        if err != nil || this.mconf.ManualStack {
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
        this.Stackinfo = ParseStack(content, this.GetOpt(), this.UnwindBuffer)
    } else if this.rec.ExtraOptions.ShowRegs {
        err = this.RegsBuffer.ParseContext(this.buf)
        if err != nil {
            panic(fmt.Sprintf("UnwindStack ParseContext failed, err:%v", err))
        }
    }
    return nil
}
