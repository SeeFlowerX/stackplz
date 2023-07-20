package event

// // #include <load_so.h>
// // #cgo LDFLAGS: -ldl
// import "C"

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/pkg/util"
    "stackplz/user/config"
    "strconv"
    "strings"
)

type UprobeEvent struct {
    ContextEvent
    mconf        *config.ModuleConfig
    Stackinfo    string
    RegsBuffer   RegsBuf
    UnwindBuffer UnwindBuf
    RegName      string
    UUID         string
}

func (this *UprobeEvent) Decode() (err error) {
    buf := this.buf
    // // 感觉输出 指定地址/寄存器 的内存视图很鸡肋 为什么不用其他工具呢 先不要了吧
    // if err = binary.Read(buf, binary.LittleEndian, &this.Buffer); err != nil {
    //     return
    // }
    // this.BufferHex = util.HexDumpGreen(this.Buffer[:])

    if this.rec.UnwindStack {
        // 理论上应该是不需要读取这4字节 但是实测需要 原因未知
        var pad uint32
        if err = binary.Read(buf, binary.LittleEndian, &pad); err != nil {
            return
        }
        // 读取完整的栈数据和寄存器数据 并解析为 UnwindBuf 结构体
        if err = binary.Read(buf, binary.LittleEndian, &this.UnwindBuffer); err != nil {
            return
        }
        // 立刻获取堆栈信息 对于某些hook点前后可能导致maps发生变化的 堆栈可能不准确
        // 这里后续可以调整为只dlopen一次 拿到要调用函数的handle 不要重复dlopen
        this.Stackinfo = ParseStack(this.pid, this.UnwindBuffer)
    } else if this.rec.Regs {
        var pad uint32
        if err = binary.Read(buf, binary.LittleEndian, &pad); err != nil {
            return
        }
        // 读取寄存器数据 并解析为 RegsBuffer 结构体
        if err = binary.Read(buf, binary.LittleEndian, &this.RegsBuffer); err != nil {
            return
        }
        this.Stackinfo = ""
    } else {
        this.Stackinfo = ""
    }
    return nil
}

func (this *UprobeEvent) Clone() IEventStruct {
    event := new(UprobeEvent)
    return event
}

func (this *UprobeEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.pid, this.tid, util.B2STrim(this.comm[:]))
}

func (this *UprobeEvent) String() string {
    var s string
    s = fmt.Sprintf("[%s_%s]", this.GetUUID(), util.B2STrim(this.comm[:]))
    if this.RegName != "" {
        // 如果设置了寄存器名字 那么尝试从获取到的寄存器数据中取值计算偏移
        // 当然前提是取了寄存器数据
        var tmp_regs [33]uint64
        if this.rec.UnwindStack {
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
            info, err := util.ParseReg(this.pid, regvalue)
            if err != nil {
                fmt.Printf("ParseReg for %s=0x%x failed", this.RegName, regvalue)
            } else {
                s += fmt.Sprintf(", Reg %s Info:\n%s", this.RegName, info)
            }
        }
    }
    if this.rec.Regs {
        var tmp_regs [33]uint64
        if this.rec.UnwindStack {
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
        if this.rec.Regs {
            s += fmt.Sprintf("\nStackinfo:\n%s", this.Stackinfo)
        } else {
            s += fmt.Sprintf(", Stackinfo:\n%s", this.Stackinfo)
        }
    }
    return s
}
