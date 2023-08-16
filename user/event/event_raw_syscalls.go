package event

import (
    "encoding/binary"
    "fmt"
    "stackplz/pkg/util"
    "stackplz/user/config"
)

type SyscallDataEvent struct {
    mconf *config.SyscallConfig
    ContextEvent
    NR uint64
}

func (this *SyscallDataEvent) CastConf() {
    p, ok := (this.conf).(*config.SyscallConfig)
    if ok {
        this.mconf = p
    } else {
        panic("SyscallDataEvent.SetConf() cast to SyscallConfig failed")
    }
}

func (this *SyscallDataEvent) Decode() (err error) {
    if err = binary.Read(this.buf, binary.LittleEndian, &this.NR); err != nil {
        return err
    }
    return nil
}

func (this *SyscallDataEvent) Clone() IEventStruct {
    event := new(SyscallDataEvent)
    return event
}

func (this *SyscallDataEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
}

func (this *SyscallDataEvent) String() string {
    err := this.ParsePadding()
    if err != nil {
        panic(fmt.Sprintf("ParsePadding failed, err:%v", err))
    }
    err = this.ParseContextStack()
    if err != nil {
        panic(fmt.Sprintf("ParseContextStack failed, err:%v", err))
    }
    var s string
    s = fmt.Sprintf("[%s] NR:%d", this.GetUUID(), this.NR)
    s = this.GetStackTrace(s)
    return s
}
