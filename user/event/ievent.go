package event

type EventType uint8

const (
    // EventTypeOutput upload to server or write to logfile.
    EventTypeOutput EventType = iota

    // EventTypeModuleData set as module cache data
    EventTypeModuleData

    // EventTypeEventProcessor display by event_processor.
    EventTypeEventProcessor
)

type IEventStruct interface {
    Decode(payload []byte, unwind_stack, regs bool) (err error)
    String() string
    Clone() IEventStruct
    EventType() EventType
    GetUUID() string
}
