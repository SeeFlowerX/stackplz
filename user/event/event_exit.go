package event

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/user/config"
)

type ExitEvent struct {
    CommonEvent
    config.ExitFields
}

func (this *ExitEvent) String() string {
    if this.mconf.FmtJson {
        data, err := json.Marshal(&this.ExitFields)
        if err != nil {
            panic(err)
        }
        return string(data)
    }

    // time 是自开机以来所经过的时间
    // 单位为 纳秒 换算关系如下
    // 1000ns = 1us
    // 1000us = 1ms
    // 1000ms = 1s
    var s string
    s = fmt.Sprintf("[ExitEvent] %s ppid=%d ptid=%d time=%d", this.GetUUID(), this.Ppid, this.Ptid, this.Time)
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
    this.ReadValue(&this.Ppid)
    this.ReadValue(&this.Tid)
    this.ReadValue(&this.Ptid)
    this.ReadValue(&this.Time)
    if this.mconf.Debug {
        this.logger.Printf(this.String())
    }
    return nil
}
