package event_processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/event"
)

const MAX_DATA_SIZE = 1024 * 4

type BaseEvent struct {
    event_type event.EventType
    DataType   int64
    Timestamp  uint64
    Pid        uint32
    Tid        uint32
    Data       [MAX_DATA_SIZE]byte
    Data_len   int32
    Comm       [16]byte
    Fd         uint32
    Version    int32
}

// 默认事件实现 暂时没有用到 暂且保留作为参考

func (this *BaseEvent) Decode(payload []byte, unwind_stack bool) (err error) {
    buf := bytes.NewBuffer(payload)
    if err = binary.Read(buf, binary.LittleEndian, &this.DataType); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Timestamp); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Tid); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Data); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Data_len); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Comm); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Fd); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Version); err != nil {
        return
    }

    return nil
}

func (this *BaseEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d_%s_%d_%d", this.Pid, this.Tid, CToGoString(this.Comm[:]), this.Fd, this.DataType)
}

func (this *BaseEvent) Payload() []byte {
    return this.Data[:this.Data_len]
}

func (this *BaseEvent) PayloadLen() int {
    return int(this.Data_len)
}

func (this *BaseEvent) StringHex() string {
    s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d", this.Pid, CToGoString(this.Comm[:]), this.Tid)
    return s
}

func (this *BaseEvent) String() string {

    s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d", this.Pid, bytes.TrimSpace(this.Comm[:]), this.Tid)
    return s
}

func (this *BaseEvent) Clone() event.IEventStruct {
    e := new(BaseEvent)
    e.event_type = event.EventTypeOutput
    return e
}

func (this *BaseEvent) EventType() event.EventType {
    return this.event_type
}

func CToGoString(c []byte) string {
    n := -1
    for i, b := range c {
        if b == 0 {
            break
        }
        n = i
    }
    return string(c[:n+1])
}
