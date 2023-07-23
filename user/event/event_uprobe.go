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
    Stackinfo    string
    RegsBuffer   RegsBuf
    UnwindBuffer UnwindBuf
    RegName      string
    UUID         string
    uprobe_point *config.UprobeArgs
    probe_index  Arg_probe_index
    lr           Arg_reg
    sp           Arg_reg
    pc           Arg_reg
    arg_str      string
}

func (this *UprobeEvent) ParseContext() (err error) {
    // this.logger.Printf("UprobeEvent eventid:%d RawSample:\n%s", this.eventid, util.HexDump(this.rec.RawSample, util.COLORRED))
    if err = binary.Read(this.buf, binary.LittleEndian, &this.probe_index); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.lr); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pc); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.sp); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    // 根据预设索引解析参数
    if (this.probe_index.Value + 1) > uint32(len(this.mconf.StackUprobeConf.Points)) {
        panic(fmt.Sprintf("probe_index %d bigger than points", this.probe_index.Value))
    }
    this.uprobe_point = &this.mconf.StackUprobeConf.Points[this.probe_index.Value]
    var results []string
    for _, point_arg := range this.uprobe_point.Args {
        var ptr Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        // if this.mconf.Debug {
        //     this.logger.Printf("[buf] len:%d cap:%d off:%d", this.buf.Len(), this.buf.Cap(), this.buf.Cap()-this.buf.Len())
        // }
        base_arg_str := fmt.Sprintf("%s=0x%x", point_arg.ArgName, ptr.Address)
        point_arg.SetValue(base_arg_str)
        // if this.mconf.Debug {
        //     point_arg.AppendValue(ptr.Format())
        // }
        if point_arg.Type == config.TYPE_NUM {
            results = append(results, point_arg.ArgValue)
            continue
        }
        // if point_arg.ReadFlag == config.UPROBE_ENTER_READ {
        //     results = append(results, point_arg.ArgValue)
        //     continue
        // }

        this.ParseArgByType(&point_arg, ptr)
        results = append(results, point_arg.ArgValue)
    }
    this.arg_str = "(" + strings.Join(results, ", ") + ")"
    this.ParsePadding()
    err = this.ParseContextStack()
    if err != nil {
        panic(fmt.Sprintf("ParseContextStack err:%v", err))
        // return err
    }
    return nil
}

func (this *UprobeEvent) Decode() (err error) {
    return nil
}

func (this *UprobeEvent) ParseContextStack() (err error) {
    if this.rec.UnwindStack {
        // 理论上应该是不需要读取这4字节 但是实测需要 原因未知
        // var pad uint32
        // if err = binary.Read(this.buf, binary.LittleEndian, &pad); err != nil {
        //     panic(fmt.Sprintf("binary.Read err:%v", err))
        // }
        // 读取完整的栈数据和寄存器数据 并解析为 UnwindBuf 结构体
        if err = binary.Read(this.buf, binary.LittleEndian, &this.UnwindBuffer); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        // 立刻获取堆栈信息 对于某些hook点前后可能导致maps发生变化的 堆栈可能不准确
        // 这里后续可以调整为只dlopen一次 拿到要调用函数的handle 不要重复dlopen
        this.Stackinfo = ParseStack(this.pid, this.UnwindBuffer)
    } else if this.rec.Regs {
        var pad uint32
        if err = binary.Read(this.buf, binary.LittleEndian, &pad); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
        // 读取寄存器数据 并解析为 RegsBuffer 结构体
        if err = binary.Read(this.buf, binary.LittleEndian, &this.RegsBuffer); err != nil {
            panic(fmt.Sprintf("binary.Read err:%v", err))
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
    s = fmt.Sprintf("[%s] %s%s LR:0x%x PC:0x%x SP:0x%x", this.GetUUID(), this.uprobe_point.PointName, this.arg_str, this.lr.Address, this.pc.Address, this.sp.Address)

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
