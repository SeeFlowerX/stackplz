package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

type ExitEvent struct {
    CommonEvent
    pid       uint32
    ppid      uint32
    tid       uint32
    ptid      uint32
    time      uint64
    sample_id []byte
}

func (this *ExitEvent) Decode() (err error) {
    return nil
}

func (this *ExitEvent) String() string {
    // time 是自开机以来所经过的时间
    // 单位为 纳秒 换算关系如下
    // 1000ns = 1us
    // 1000us = 1ms
    // 1000ms = 1s
    var s string
    s = fmt.Sprintf("[PERF_RECORD_EXIT] %s ppid:%d ptid:%d time:%d", this.GetUUID(), this.ppid, this.ptid, this.time)
    return s
}

func (this *ExitEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.pid, this.tid)
}

func (this *ExitEvent) ParseContext() (err error) {
    // 直接一次性解析完成好了...
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.ppid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.tid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.ptid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.time); err != nil {
        return err
    }
    return nil
}
