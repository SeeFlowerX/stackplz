package event

import (
    "encoding/json"
    "fmt"
    "stackplz/user/common"
    "stackplz/user/config"
    "stackplz/user/util"
)

type SyscallEvent struct {
    ContextEvent
    UUID         string
    RegsBuffer   RegsBuf
    UnwindBuffer UnwindBuf
    nr_point     *config.SyscallPoint
    config.SyscallFields
    Stack_str string
}

func (this *SyscallEvent) DumpRecord() bool {
    return this.mconf.DumpRecord(common.SYSCALL_EVENT, &this.rec)
}

func (this *SyscallEvent) ParseEvent() (IEventStruct, error) {
    data_e, err := this.ContextEvent.ParseEvent()
    if err != nil {
        panic("...")
    }
    if data_e == nil {
        if err := this.ParseContext(); err != nil {
            panic(fmt.Sprintf("SyscallEvent.ParseContext() err:%v", err))
        }
        return this, nil
    }
    return data_e, nil
}

func (this *SyscallEvent) ParseContext() (err error) {
    this.ReadArg(&this.NR)

    this.nr_point = this.mconf.SysCallConf.GetSyscallPointByNR(this.NR)
    // this.nr_point = config.GetSyscallPointByNR(this.NR)
    this.PointName = this.nr_point.Name

    // this.logger.Printf("ParseContext EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
    this.PointValue = nil
    this.PointStr = ""
    if this.EventId == SYSCALL_ENTER {
        this.ReadArg(&this.LR)
        this.ReadArg(&this.SP)
        this.ReadArg(&this.PC)
        if this.mconf.FmtJson {
            this.PointValue = this.nr_point.ParsePointJson(this.buf, config.EBPF_SYS_ENTER)
        } else {
            this.PointStr = this.nr_point.ParseEnterPoint(this.buf)
        }
    } else if this.EventId == SYSCALL_EXIT {
        if this.mconf.FmtJson {
            this.PointValue = this.nr_point.ParsePointJson(this.buf, config.EBPF_SYS_EXIT)
        } else {
            this.PointStr = this.nr_point.ParseExitPoint(this.buf)
        }
    } else {
        panic(fmt.Sprintf("SyscallEvent.ParseContext() failed, EventId:%d", this.EventId))
    }
    this.ParsePadding()
    err = this.ParseContextStack()
    if err != nil {
        panic(fmt.Sprintf("ParseContextStack err:%v", err))
    }
    if this.mconf.AutoResume {
        LetItResume(this.Pid)
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

func (this *SyscallEvent) MarshalJSON() ([]byte, error) {
    type ContextAlias config.ContextFields
    type SyscallAlias config.SyscallFields
    if this.EventId == SYSCALL_ENTER {
        return json.Marshal(&struct {
            Event string `json:"event"`
            Comm  string `json:"comm"`
            *ContextAlias
            LR string `json:"lr"`
            SP string `json:"sp"`
            PC string `json:"pc"`
            *SyscallAlias
            Stack_str string `json:"stack_str"`
        }{
            Event:        "sys_enter",
            Comm:         util.B2STrim(this.Comm[:]),
            ContextAlias: (*ContextAlias)(&this.ContextFields),
            LR:           fmt.Sprintf("0x%x", this.LR),
            SP:           fmt.Sprintf("0x%x", this.SP),
            PC:           fmt.Sprintf("0x%x", this.PC),
            SyscallAlias: (*SyscallAlias)(&this.SyscallFields),
            Stack_str:    this.Stack_str,
        })
    }
    return json.Marshal(&struct {
        Event string `json:"event"`
        Comm  string `json:"comm"`
        *ContextAlias
        *SyscallAlias
        Stack_str string `json:"stack_str"`
    }{
        Event:        "sys_exit",
        Comm:         util.B2STrim(this.Comm[:]),
        ContextAlias: (*ContextAlias)(&this.ContextFields),
        SyscallAlias: (*SyscallAlias)(&this.SyscallFields),
        Stack_str:    this.Stack_str,
    })
}

func (this *SyscallEvent) String() string {
    this.Stack_str = ""
    if this.EventId == SYSCALL_ENTER {
        this.Stack_str = this.GetStackTrace(this.Stack_str)
    }
    if this.mconf.FmtJson {
        data, err := json.Marshal(this)
        if err != nil {
            panic(err)
        }
        return string(data)
    }
    var base_str string
    base_str = fmt.Sprintf("[%s] %s%s", this.GetUUID(), this.nr_point.Name, this.PointStr)
    if this.EventId == SYSCALL_ENTER {
        var lr_str string
        var pc_str string
        if this.mconf.GetOff {
            lr_str = fmt.Sprintf("LR:0x%x(%s)", this.LR, this.GetOffset(this.LR))
            pc_str = fmt.Sprintf("PC:0x%x(%s)", this.PC, this.GetOffset(this.PC))
        } else {
            lr_str = fmt.Sprintf("LR:0x%x", this.LR)
            pc_str = fmt.Sprintf("PC:0x%x", this.PC)
        }
        base_str = fmt.Sprintf("%s %s %s SP:0x%x", base_str, lr_str, pc_str, this.SP)
    }
    return base_str + this.Stack_str
}

func (this *SyscallEvent) Clone() IEventStruct {
    event := new(SyscallEvent)
    return event
}
