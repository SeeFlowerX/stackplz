package event

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/user/config"
    "stackplz/user/util"
)

type CommEvent struct {
    CommonEvent
    config.BPF_record_comm
}

func (this *CommEvent) JsonString(stack_str string) string {
    v := config.FMT_record_comm{}
    v.Event = "comm"
    v.Pid = this.Pid
    v.Tid = this.Tid
    v.Comm = this.Comm
    data, err := json.Marshal(v)
    if err != nil {
        panic(err)
    }
    return string(data)
}

func (this *CommEvent) String() string {
    var s string
    s = fmt.Sprintf("[PERF_RECORD_COMM] %s", this.GetUUID())
    return s
}

func (this *CommEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d_%s", this.Pid, this.Tid, this.Comm)
}

func (this *CommEvent) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    // 来源于自己的通通不管
    if this.mconf.SelfPid == this.Pid {
        return nil
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }
    var tmp = make([]byte, this.buf.Len())
    if err = binary.Read(this.buf, binary.LittleEndian, &tmp); err != nil {
        return err
    }
    this.Comm = util.B2STrim(tmp)
    if this.mconf.FmtJson {
        this.logger.Printf(this.JsonString(""))
    }
    // if this.mconf.Debug {
    //     s := fmt.Sprintf("[CommEvent] pid=%d tid=%d comm=<%s>", this.Pid, this.Tid, this.Comm)
    //     this.logger.Printf(s)
    // }
    return nil
}
