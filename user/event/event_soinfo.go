package event

// #include <load_so.h>
// #cgo LDFLAGS: -ldl
import "C"

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

// 格式化输出相关

const CHUNK_SIZE = 16
const CHUNK_SIZE_HALF = CHUNK_SIZE / 2

const (
    COLORRESET  = "\033[0m"
    COLORRED    = "\033[31m"
    COLORGREEN  = "\033[32m"
    COLORYELLOW = "\033[33m"
    COLORBLUE   = "\033[34m"
    COLORPURPLE = "\033[35m"
    COLORCYAN   = "\033[36m"
    COLORWHITE  = "\033[37m"
)

func dumpByteSlice(b []byte, perfix string) *bytes.Buffer {
    var a [CHUNK_SIZE]byte
    bb := new(bytes.Buffer)
    n := (len(b) + (CHUNK_SIZE - 1)) &^ (CHUNK_SIZE - 1)

    for i := 0; i < n; i++ {

        // 序号列
        if i%CHUNK_SIZE == 0 {
            bb.WriteString(perfix)
            bb.WriteString(fmt.Sprintf("%04d", i))
        }

        // 长度的一半，则输出4个空格
        if i%CHUNK_SIZE_HALF == 0 {
            bb.WriteString("    ")
        } else if i%(CHUNK_SIZE_HALF/2) == 0 {
            bb.WriteString("  ")
        }

        if i < len(b) {
            bb.WriteString(fmt.Sprintf(" %02X", b[i]))
        } else {
            bb.WriteString("  ")
        }

        // 非ASCII 改为 .
        if i >= len(b) {
            a[i%CHUNK_SIZE] = ' '
        } else if b[i] < 32 || b[i] > 126 {
            a[i%CHUNK_SIZE] = '.'
        } else {
            a[i%CHUNK_SIZE] = b[i]
        }

        // 如果到达size长度，则换行
        if i%CHUNK_SIZE == (CHUNK_SIZE - 1) {
            bb.WriteString(fmt.Sprintf("    %s\n", string(a[:])))
        }
    }
    return bb
}

type SoInfoEvent struct {
    event_type EventType
    Pid        uint32
    Tid        uint32
    Comm       [16]byte
    BaseAddr   uint64
    RealPath   [256]byte
    Buffer     [256]byte
    BufferHex  string
    UUID       string
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
    if err = binary.Read(buf, binary.LittleEndian, &this.RealPath); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Buffer); err != nil {
        return
    }
    b := dumpByteSlice(this.Buffer[:], COLORGREEN)
    b.WriteString(COLORRESET)
    this.BufferHex = b.String()

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

func (this *SoInfoEvent) SetUUID(uuid string) {
    this.UUID = uuid
}

func (this *SoInfoEvent) String() string {
    var s string
    s = fmt.Sprintf("[%s] PID:%d, Comm:%s", this.UUID, this.Pid, bytes.TrimSpace(bytes.Trim(this.Comm[:], "\x00")))
    // s += fmt.Sprintf(", RealPath:%s BufferHex:\n%s", this.RealPath, this.BufferHex)
    s += fmt.Sprintf(", Base:0x%x %s", this.BaseAddr, this.RealPath)
    return s
}
