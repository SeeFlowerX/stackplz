package event

import (
    "encoding/json"
    "fmt"
    "stackplz/pkg/util"
    "stackplz/user/config"
    "strconv"
    "strings"
)

type HookDataEvent struct {
    mconf *config.ProbeConfig
    ContextEvent
}

func (this *HookDataEvent) CastConf() {
    p, ok := (this.conf).(*config.ProbeConfig)
    if ok {
        this.mconf = p
    } else {
        panic("SyscallDataEvent.SetConf() cast to ProbeConfig failed")
    }
}

func (this *HookDataEvent) Decode() (err error) {
    return nil
}

func (this *HookDataEvent) Clone() IEventStruct {
    event := new(HookDataEvent)
    return event
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
