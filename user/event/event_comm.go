package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "stackplz/user/util"
)

type CommEvent struct {
    CommonEvent
    Pid       uint32
    Tid       uint32
    Comm      string
    Sample_id []byte
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
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    // 来源于自己的通通不管
    if this.mconf.SelfPid == this.Pid {
        return nil
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    var tmp = make([]byte, this.buf.Len())
    if err = binary.Read(this.buf, binary.LittleEndian, &tmp); err != nil {
        panic(fmt.Sprintf("binary.Read err:%v", err))
    }
    this.Comm = util.B2STrim(tmp)
    if this.mconf.Debug {
        s := fmt.Sprintf("[CommEvent] pid=%d tid=%d comm=<%s>", this.Pid, this.Tid, this.Comm)
        this.logger.Printf(s)
    }
    return nil
}
