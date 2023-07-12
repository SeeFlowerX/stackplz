package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

type ForkEvent struct {
    CommonEvent
    pid       uint32
    ppid      uint32
    tid       uint32
    ptid      uint32
    time      uint64
    sample_id []byte
}

func (this *ForkEvent) Decode() (err error) {
    return nil
}

func (this *ForkEvent) String() string {
    var s string
    s = fmt.Sprintf("[PERF_RECORD_FORK] %s ppid:%d ptid:%d time:%d", this.GetUUID(), this.ppid, this.ptid, this.time)
    return s
}

func (this *ForkEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.pid, this.tid)
}

func (this *ForkEvent) ParseContext() (err error) {
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
