package event

// #include <load_so.h>
// #cgo LDFLAGS: -ldl
import "C"

import (
    "encoding/binary"
    "fmt"
    "stackplz/pkg/util"
    "stackplz/user/config"
)

type LibInfo struct {
    Pid      uint32
    BaseAddr uint64
    LibSize  uint64
    LibPath  string
}

type MapsHelper map[uint32]PidMaps
type PidMaps map[string][]LibInfo

func NewMapsHelper() *MapsHelper {
    helper := &MapsHelper{}
    return helper
}

func (this *MapsHelper) UpdateMaps(soinfo *SoInfoEvent) {
    pid_maps, ok := (*this)[soinfo.Pid]
    if !ok {
        (*this)[soinfo.Pid] = PidMaps{}
    }
    info := LibInfo{
        LibSize:  soinfo.LibSize,
        BaseAddr: soinfo.BaseAddr,
        LibPath:  soinfo.LibPath,
    }
    base_list, ok := pid_maps[soinfo.LibPath]
    if ok {
        // 注意基址列表去重 做成列表的原因是...
        has_find := false
        for _, info := range base_list {
            if info.BaseAddr == info.BaseAddr {
                has_find = true
                break
            }
        }
        if !has_find {
            base_list = append(base_list, info)
        }
    } else {
        pid_maps[soinfo.LibPath] = []LibInfo{info}
    }
}

func (this *MapsHelper) GetOffset(addr uint64) (info string) {
    return ""
}

var maps_helper = NewMapsHelper()

type SoInfoEvent struct {
    event_type EventType
    KEvent
    mconf    *config.ModuleConfig
    Pid      uint32
    Tid      uint32
    Comm     [16]byte
    BaseAddr uint64
    LibSize  uint64
    LibPath  string
    RealPath [256]byte
    UUID     string
}

func (this *SoInfoEvent) Decode() (err error) {
    // buf := bytes.NewBuffer(payload)
    // if err = binary.Read(buf, binary.LittleEndian, &this.Pid); err != nil {
    //     return
    // }
    // if err = binary.Read(buf, binary.LittleEndian, &this.Tid); err != nil {
    //     return
    // }
    buf := this.buf
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
    this.LibPath = util.B2STrim(this.RealPath[:])

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

// func (this *SoInfoEvent) GetUUID() string {
//     return fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
// }

func (this *SoInfoEvent) String() string {
    var s string
    s = fmt.Sprintf("[%s_%s]", this.GetUUID(), util.B2STrim(this.Comm[:]))
    s += fmt.Sprintf(", Base:0x%x Size:0x%x %s", this.BaseAddr, this.LibSize, this.LibPath)
    return s
}
