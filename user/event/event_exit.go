package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

type ExitEvent struct {
    CommonEvent
    Pid       uint32
    Ppid      uint32
    Tid       uint32
    Ptid      uint32
    Time      uint64
    Sample_id []byte
}

func (this *ExitEvent) String() string {
    // time 是自开机以来所经过的时间
    // 单位为 纳秒 换算关系如下
    // 1000ns = 1us
    // 1000us = 1ms
    // 1000ms = 1s
    var s string
    s = fmt.Sprintf("[PERF_RECORD_EXIT] %s ppid:%d ptid:%d time:%d", this.GetUUID(), this.Ppid, this.Ptid, this.Time)
    return s
}

func (this *ExitEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.Pid, this.Tid)
}

func (this *ExitEvent) ParseContext() (err error) {
    // 直接一次性解析完成好了...
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
        s := fmt.Sprintf("[ExitEvent] pid=%d ppid=%d tid=%d ptid=%d time=%d", this.Pid, this.Ppid, this.Tid, this.Ptid, this.Time)
        this.logger.Printf(s)
    }
    return nil
}
