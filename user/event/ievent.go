package event

type EventType uint8

const (
    // EventTypeModuleData set as module cache data
    EventTypeModuleData = 0
)

type IEventStruct interface {
    Decode(payload []byte, unwind_stack, regs bool) (err error)
    String() string
    Clone() IEventStruct
    EventType() EventType
    SetUUID(string)
}
