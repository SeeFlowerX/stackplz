package event

// // #include <load_so.h>
// // #cgo LDFLAGS: -ldl
// import "C"

import (
	"encoding/binary"
	"fmt"
	"stackplz/user/config"
	"stackplz/user/util"
	"strings"
)

type UprobeEvent struct {
    ContextEvent
    UUID         string
    uprobe_point *config.UprobeArgs
    probe_index  Arg_probe_index
    lr           Arg_reg
    sp           Arg_reg
    pc           Arg_reg
    arg_str      string
}

func (this *UprobeEvent) ParseContext() (err error) {
    // this.logger.Printf("UprobeEvent EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
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

func (this *UprobeEvent) Clone() IEventStruct {
    event := new(UprobeEvent)
    return event
}

func (this *UprobeEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
}

func (this *UprobeEvent) String() string {

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
    s = this.GetStackTrace(s)

    return s
}
