package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "stackplz/user/common"
    "stackplz/user/util"
)

var hit_count uint32 = 0

type BrkEvent struct {
    ContextEvent
    EventAddr uint64
    UUID      string
}

func (this *BrkEvent) String() (s string) {
    s = fmt.Sprintf("[%s] event_addr:0x%x hit_count:%d", this.GetUUID(), this.EventAddr, hit_count)
    s = this.GetStackTrace(s)
    return s
}

func (this *BrkEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d", this.Pid, this.Tid)
}

func (this *BrkEvent) Check() bool {
    // 排除自己
    if this.Pid == this.mconf.SelfPid {
        return false
    }
    // 必须是来自给定 pid 的事件
    if this.Pid != this.GetPid() {
        return false
    }
    // 排除内核
    // if this.Pid == 0 {
    //     return false
    // }
    // 只记录最开始指定的pid
    // if this.Pid != this.mconf.PidWhitelist[0] {
    //     return false
    // }
    hit_count += 1
    return true
}

func (this *BrkEvent) DumpRecord() bool {
    return this.mconf.DumpRecord(common.BRK_EVENT, &this.rec)
}

func (this *BrkEvent) ParseEvent() (IEventStruct, error) {
    // 直接调用 ParseContext 即可 不需要先调用一遍 this.ContextEvent.ParseEvent()
    if err := this.ParseContext(); err != nil {
        panic(fmt.Sprintf("SyscallEvent.ParseContext() err:%v", err))
    }
    this.Check()
    return this, nil
}

func (this *BrkEvent) ParseContext() (err error) {
    this.EventId = HW_BREAKPOINT
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    if this.Pid != this.GetPid() {
        return nil
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.EventAddr); err != nil {
        return err
    }
    this.ParseContextStack()

    return nil
}

func (this *BrkEvent) Clone() IEventStruct {
    event := new(BrkEvent)
    return event
}

func (this *BrkEvent) GetPid() uint32 {
    if len(this.mconf.PidWhitelist) == 1 {
        return this.mconf.PidWhitelist[0]
    }
    if this.mconf.BrkPid == -1 {
        return this.Pid
    }
    return uint32(this.mconf.BrkPid)
}

func (this *BrkEvent) ParseContextStack() {
    this.Stackinfo = ""
    if this.rec.ExtraOptions.UnwindStack {
        // 读取完整的栈数据和寄存器数据 并解析为 UnwindBuf 结构体
        this.UnwindBuffer = &UnwindBuf{}
        err := this.UnwindBuffer.ParseContext(this.buf)
        if err != nil {
            panic(fmt.Sprintf("UnwindStack ParseContext failed, err:%v", err))
        }
        // 立刻获取堆栈信息 对于某些hook点前后可能导致maps发生变化的 堆栈可能不准确
        // 这里后续可以调整为只dlopen一次 拿到要调用函数的handle 不要重复dlopen
        content, err := util.ReadMapsByPid(this.GetPid())
        if err != nil || this.mconf.ManualStack {
            // 直接读取 maps 失败 那么从 mmap2 事件中获取
            // 根据测试结果 有这样的情况 -> 即 fork 产生的子进程 那么应该查找其父进程 mmap2 事件
            maps_helper.SetLogger(this.logger)
            info, err := maps_helper.GetStack(this.GetPid(), this.UnwindBuffer)
            if err != nil {
                this.logger.Printf("Error when GetStack:%v", err)
            } else {
                this.Stackinfo = info
            }
            return
        }
        opt := &UnwindOption{}
        opt.RegMask = (1 << 33) - 1
        opt.ShowPC = this.mconf.ShowPC
        this.Stackinfo = ParseStack(content, opt, this.UnwindBuffer)
    } else if this.rec.ExtraOptions.ShowRegs {
        err := this.RegsBuffer.ParseContext(this.buf)
        if err != nil {
            panic(fmt.Sprintf("UnwindStack ParseContext failed, err:%v", err))
        }
    }
    return
}
