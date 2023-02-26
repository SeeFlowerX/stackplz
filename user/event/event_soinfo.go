package event

// #include <load_so.h>
// #cgo LDFLAGS: -ldl
import "C"

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "stackplz/pkg/util"
    "stackplz/user/config"
)

type SoInfoEvent struct {
    event_type EventType
    Pid        uint32
    Tid        uint32
    Comm       [16]byte
    BaseAddr   uint64
    LibSize    uint64
    RealPath   [256]byte
    UUID       string
}

func (this *SoInfoEvent) SetConf(conf config.IConfig) {
    // panic("SoInfoEvent.SetConf() not implemented yet")
}

func (this *SoInfoEvent) Decode(payload []byte, unwind_stack, regs bool) (err error) {
    buf := bytes.NewBuffer(payload)
    if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Tid); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.BaseAddr); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.LibSize); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.RealPath); err != nil {
        return
    }

    return nil
}

func (this *SoInfoEvent) Clone() IEventStruct {
    event := new(SoInfoEvent)
    event.event_type = EventTypeSoInfoData
    return event
}

func (this *SoInfoEvent) EventType() EventType {
    return this.event_type
}

func (this *SoInfoEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
}

func (this *SoInfoEvent) String() string {
    var s string
    s = fmt.Sprintf("[%s]", this.GetUUID())
    s += fmt.Sprintf(", Base:0x%x Size:0x%x %s", this.BaseAddr, this.LibSize, util.B2STrim(this.RealPath[:]))
    return s
}
