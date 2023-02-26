package event

import "stackplz/user/config"

type EventType uint8

const (
    EventTypeSoInfoData = iota
    EventTypeSysCallData
    EventTypeModuleData
)

type IEventStruct interface {
    Decode(payload []byte, unwind_stack, regs bool) (err error)
    String() string
    Clone() IEventStruct
    EventType() EventType
    GetUUID() string
    SetConf(config.IConfig)
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
