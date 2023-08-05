package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

type ForkEvent struct {
    CommonEvent
    Pid       uint32
    Ppid      uint32
    Tid       uint32
    Ptid      uint32
    Time      uint64
    Sample_id []byte
}

func (this *ForkEvent) String() string {
    var s string
    s = fmt.Sprintf("[PERF_RECORD_FORK] %s ppid:%d ptid:%d time:%d", this.GetUUID(), this.Ppid, this.Ptid, this.Time)
    return s
}

func (this *ForkEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.Pid, this.Tid)
}

func (this *ForkEvent) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    // 来源于自己的通通不管
    if this.mconf.SelfPid == this.Pid {
        return nil
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Ppid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Ptid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Time); err != nil {
        return err
    }
    if this.mconf.Debug {
        s := fmt.Sprintf("[ForkEvent] pid=%d ppid=%d tid=%d ptid=%d time=%d", this.Pid, this.Ppid, this.Tid, this.Ptid, this.Time)
        this.logger.Printf(s)
    }
    maps_helper.UpdateForkEvent(this)
    return nil
}
