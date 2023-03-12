package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "stackplz/user/config"
)

type EventType uint8

const (
    EventTypeSoInfoData = iota
    EventTypeSysCallData
    EventTypeModuleData
)

type IEventStruct interface {
    Decode() (err error)
    String() string
    Clone() IEventStruct
    EventType() EventType
    GetUUID() string
    PrePareUUID() error
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

type KEvent struct {
    child        IEventStruct
    mconf        *config.ModuleConfig
    payload      []byte
    unwind_stack bool
    show_regs    bool
    Pid          uint32
    Tid          uint32
    buf          *bytes.Buffer
}

func (this *KEvent) String() string {
    panic("KEvent.Dispaly() not implemented yet")
}

func (this *KEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.Pid, this.Tid)
}

func (this *KEvent) PrePareUUID() (err error) {
    // 在完整payload正式交由单独的worker处理前 在 processer 拿到事件后
    // 先简单解析下pid和tid信息 为每一个线程设置一个worker
    this.buf = bytes.NewBuffer(this.payload)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }
    return nil
}

func (this *KEvent) SetPayload(payload []byte) {
    this.payload = payload
}

func (this *KEvent) SetUnwindStack(unwind_stack bool) {
    this.unwind_stack = unwind_stack
}

func (this *KEvent) SetShowRegs(show_regs bool) {
    this.show_regs = show_regs
}

func (this *KEvent) SetConf(conf config.IConfig) {
    // 原生指针转换 conf 是指针的时候 但不能是 interface
    // this.mconf = (*config.ModuleConfig)(unsafe.Pointer(conf))
    p, ok := (conf).(*config.ModuleConfig)
    if ok {
        this.mconf = p
    } else {
        panic("KEvent.SetConf() cast to ModuleConfig failed")
    }
}
