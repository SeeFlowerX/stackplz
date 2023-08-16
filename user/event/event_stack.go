package event

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/pkg/util"
    "strconv"
    "strings"
)

type HookDataEvent struct {
    event_type EventType
    CommonEvent
    Pid          uint32
    Tid          uint32
    Timestamp    uint64
    Comm         [16]byte
    Stackinfo    string
    RegsBuffer   RegsBuf
    UnwindBuffer *UnwindBuf
    UnwindStack  bool
    ShowRegs     bool
    RegName      string
}

func (this *HookDataEvent) Decode() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.rec.SampleSize); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Timestamp); err != nil {
        return
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Comm); err != nil {
        return
    }
    return nil
}

func (this *HookDataEvent) ParseContextStack() (err error) {
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
        content, err := ReadMapsByPid(this.Pid)
        fmt.Println(content)
        if err != nil {
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

func (this *HookDataEvent) Clone() IEventStruct {
    event := new(HookDataEvent)
    event.event_type = EventTypeModuleData
    return event
}

func (this *HookDataEvent) EventType() EventType {
    return this.event_type
}

func (this *HookDataEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
}

func (this *HookDataEvent) GetStackTrace(s string) string {
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
            if regno >= 0 && regno <= 29 {
                // 取到对应的寄存器值
                regvalue = tmp_regs[regno]
                has_reg_value = true
            }
        } else if this.RegName == "lr" {
            regvalue = tmp_regs[30]
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
        for regno := 0; regno <= 29; regno++ {
            regs[fmt.Sprintf("x%d", regno)] = fmt.Sprintf("0x%x", tmp_regs[regno])
        }
        regs["lr"] = fmt.Sprintf("0x%x", tmp_regs[30])
        regs["sp"] = fmt.Sprintf("0x%x", tmp_regs[31])
        regs["pc"] = fmt.Sprintf("0x%x", tmp_regs[32])
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

func (this *HookDataEvent) String() string {
    this.Decode()
    err := this.ParsePadding()
    if err != nil {
        panic(fmt.Sprintf("ParsePadding failed, err:%v", err))
    }
    err = this.ParseContextStack()
    if err != nil {
        panic(fmt.Sprintf("ParseContextStack failed, err:%v", err))
    }
    var s string
    s = fmt.Sprintf("[%s]", this.GetUUID())
    s = this.GetStackTrace(s)
    return s
}
