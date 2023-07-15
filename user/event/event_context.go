package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

type ContextEvent struct {
    CommonEvent
    ts       uint64
    eventid  uint32
    host_tid uint32
    host_pid uint32
    tid      uint32
    pid      uint32
    uid      uint32
    comm     [16]byte
    argnum   uint8
    padding  [7]byte
}

func (this *ContextEvent) NewSyscallEvent() IEventStruct {
    event := &SyscallEvent{ContextEvent: *this}
    event.ParseContext()
    return event
}

func (this *ContextEvent) Decode() (err error) {
    return nil
}

func (this *ContextEvent) String() string {
    var s string
    s = fmt.Sprintf("[ContextEvent] %s eventid:%d argnum:%d time:%d", this.GetUUID(), this.eventid, this.argnum, this.ts)
    return s
}

func (this *ContextEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.pid, this.tid)
}

func (this *ContextEvent) GetEventId() uint32 {
    return this.eventid
}

func (this *ContextEvent) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.ts); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.eventid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.host_tid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.host_pid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.tid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.uid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.comm); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.argnum); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.padding); err != nil {
        return err
    }
    return nil
}

func (this *ContextEvent) Clone() IEventStruct {
    event := new(ContextEvent)
    // event.event_type = EventTypeSysCallData
    return event
}
