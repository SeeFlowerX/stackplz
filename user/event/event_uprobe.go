package event

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/user/config"
    "stackplz/user/util"
    "strings"
)

type UprobeEvent struct {
    ContextEvent
    UUID         string
    uprobe_point *config.UprobeArgs
    probe_index  config.Arg_probe_index
    lr           config.Arg_reg
    sp           config.Arg_reg
    pc           config.Arg_reg
    arg_str      string
}

func (this *UprobeEvent) ParseContext() (err error) {
    if err = binary.Read(this.buf, binary.LittleEndian, &this.probe_index); err != nil {
        panic(err)
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.lr); err != nil {
        panic(err)
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pc); err != nil {
        panic(err)
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.sp); err != nil {
        panic(err)
    }
    // 根据预设索引解析参数
    if (this.probe_index.Value + 1) > uint32(len(this.mconf.StackUprobeConf.Points)) {
        panic(fmt.Sprintf("probe_index %d bigger than points", this.probe_index.Value))
    }
    this.uprobe_point = &this.mconf.StackUprobeConf.Points[this.probe_index.Value]
    var results []string
    for _, point_arg := range this.uprobe_point.Args {
        var ptr config.Arg_reg
        if err = binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
            panic(err)
        }
        base_arg_str := fmt.Sprintf("%s=0x%x", point_arg.ArgName, ptr.Address)
        point_arg.SetValue(base_arg_str)
        if point_arg.BaseType == config.TYPE_NUM {
            results = append(results, point_arg.ArgValue)
            continue
        }
        this.ParseArgByType(&point_arg, ptr)
        results = append(results, point_arg.ArgValue)
    }
    this.arg_str = "(" + strings.Join(results, ", ") + ")"
    this.ParsePadding()
    err = this.ParseContextStack()
    if err != nil {
        panic(fmt.Sprintf("ParseContextStack err:%v", err))
    }
    return nil
}

func (this *UprobeEvent) Clone() IEventStruct {
    event := new(UprobeEvent)
    return event
}

func (this *UprobeEvent) GetUUID() string {
    s := fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
    if this.mconf.ShowTime {
        s = fmt.Sprintf("%d|%s", this.Ts, s)
    }
    if this.mconf.ShowUid {
        s = fmt.Sprintf("%d|%s", this.Uid, s)
    }
    return s
}

func (this *UprobeEvent) JsonString(stack_str string) string {
    v := config.UprobeFmt{}
    v.Ts = this.Ts
    v.Event = fmt.Sprintf("uprobe_%d", this.probe_index.Index)
    v.HostTid = this.HostTid
    v.HostPid = this.HostPid
    v.Tid = this.Tid
    v.Pid = this.Pid
    v.Uid = this.Uid
    v.Comm = util.B2STrim(this.Comm[:])
    v.Argnum = this.Argnum
    v.Stack = stack_str
    v.LR = fmt.Sprintf("0x%x", this.lr.Address)
    v.SP = fmt.Sprintf("0x%x", this.sp.Address)
    v.PC = fmt.Sprintf("0x%x", this.pc.Address)
    v.Arg_str = this.arg_str
    data, err := json.Marshal(v)
    if err != nil {
        panic(err)
    }
    return string(data)
}

func (this *UprobeEvent) String() string {
    stack_str := this.GetStackTrace("")
    if this.mconf.FmtJson {
        return this.JsonString(stack_str)
    }
    var lr_str string
    var pc_str string
    if this.mconf.GetOff {
        lr_str = fmt.Sprintf("LR:0x%x(%s)", this.lr.Address, this.GetOffset(this.lr.Address))
        pc_str = fmt.Sprintf("PC:0x%x(%s)", this.pc.Address, this.GetOffset(this.pc.Address))
    } else {
        lr_str = fmt.Sprintf("LR:0x%x", this.lr.Address)
        pc_str = fmt.Sprintf("PC:0x%x", this.pc.Address)
    }

    var s string
    s = fmt.Sprintf("[%s] %s%s %s %s SP:0x%x", this.GetUUID(), this.uprobe_point.PointName, this.arg_str, lr_str, pc_str, this.sp.Address)

    return s + stack_str
}
