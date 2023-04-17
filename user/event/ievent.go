package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/pkg/util"
	"stackplz/user/config"
)

type EventType uint8

const (
    EventTypeSoInfoData = iota
    EventTypeSysCallData
    EventTypeModuleData
)

const (
    SECURITY_FILE_MPROTECT uint32 = iota + 456
    SU_FILE_ACCESS
    DO_MMAP
)

type IEventStruct interface {
    Decode() (err error)
    String() string
    Clone() IEventStruct
    EventType() EventType
    GetUUID() string
    ToChildEvent() IEventStruct
    ParseContext() error
    GetEventContext() *EventContext
    SetConf(config.IConfig)
    SetPayload(payload []byte)
    SetUnwindStack(unwind_stack bool)
    SetShowRegs(show_regs bool)
}

type UnwindBuf struct {
    Abi       uint64
    Regs      [33]uint64
    StackSize uint64
    Data      [16384]byte
    DynSize   uint64
}

type RegsBuf struct {
    Abi  uint64
    Regs [33]uint64
}

type CommonEvent struct {
    mconf         *config.ModuleConfig
    payload       []byte
    event_context EventContext
    unwind_stack  bool
    show_regs     bool
    buf           *bytes.Buffer
}

func (this *CommonEvent) String() string {
    var s string
    s = fmt.Sprintf("[%s_%s]", this.GetUUID(), util.B2STrim(this.event_context.Comm[:]))
    return s
}

func (this *CommonEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.event_context.Pid, this.event_context.Tid)
}

// func (this *CommonEvent) PrePareUUID() (err error) {
//     // 在完整payload正式交由单独的worker处理前 在 processer 拿到事件后
//     // 先简单解析下pid和tid信息 为每一个线程设置一个worker
//     this.buf = bytes.NewBuffer(this.payload)
//     if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
//         return err
//     }
//     if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
//         return err
//     }
//     return nil
// }

func (this *CommonEvent) EventType() EventType {
    panic("CommonEvent.EventType() not implemented yet")
}

func (this *CommonEvent) Clone() IEventStruct {
    event := new(CommonEvent)
    // event.event_type = EventTypeSoInfoData
    return event
}

func (this *CommonEvent) Decode() (err error) {
    panic("CommonEvent.Decode() not implemented yet")
}

func (this *CommonEvent) ParseContext() (err error) {
    // 先把基础信息解析出来 后面再根据 eventid 进一步解析传递的参数
    this.buf = bytes.NewBuffer(this.payload)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.event_context); err != nil {
        return err
    }
    // fmt.Printf("CommonEvent this.buf:%p cap:%d len:%d\n", this.buf, this.buf.Cap(), this.buf.Len())
    return nil
}

func (this *CommonEvent) GetEventContext() *EventContext {
    return &this.event_context
}

func (this *CommonEvent) ToChildEvent() IEventStruct {
    // 根据具体的 eventid 转换到具体的 event
    var event IEventStruct
    switch this.event_context.EventId {
    case DO_MMAP:
        {
            event = &VmaInfoEvent{*this, "", 0, 0, 0}
            // fmt.Printf("yes, DO_MMAP %d\n", this.event_context.EventId)
        }
    default:
        {
            // panic(fmt.Sprintf("ToChildEvent failed!!! %s", this.event_context.String()))
            event = this
            // fmt.Printf("yes, CommonEvent %d\n", this.event_context.EventId)
        }
    }
    return event
}

func (this *CommonEvent) SetPayload(payload []byte) {
    this.payload = payload
}

func (this *CommonEvent) SetUnwindStack(unwind_stack bool) {
    this.unwind_stack = unwind_stack
}

func (this *CommonEvent) SetShowRegs(show_regs bool) {
    this.show_regs = show_regs
}

func (this *CommonEvent) SetConf(conf config.IConfig) {
    // 原生指针转换 conf 是指针的时候 但不能是 interface
    // this.mconf = (*config.ModuleConfig)(unsafe.Pointer(conf))
    p, ok := (conf).(*config.ModuleConfig)
    if ok {
        this.mconf = p
    } else {
        panic("CommonEvent.SetConf() cast to ModuleConfig failed")
    }
}
