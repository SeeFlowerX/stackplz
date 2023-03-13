package event

// #include <load_so.h>
// #cgo LDFLAGS: -ldl
import "C"

import (
    "encoding/binary"
    "fmt"
    "stackplz/pkg/util"
    "stackplz/user/config"
    "strings"
    "sync"
)

type LibInfo struct {
    BaseAddr uint64
    LibSize  uint64
    EndAddr  uint64
    LibPath  string
}

type MapsHelper map[uint32]PidMaps
type PidMaps map[string][]LibInfo

func NewMapsHelper() MapsHelper {
    helper := make(MapsHelper)
    return helper
}

func (this *MapsHelper) UpdateMaps(soinfo *SoInfoEvent) {
    // 拙劣的函数
    maps_lock.Lock()
    defer maps_lock.Unlock()
    pid_maps, ok := (*this)[soinfo.Pid]
    if !ok {
        pid_maps = make(PidMaps)
        (*this)[soinfo.Pid] = pid_maps
    }
    pid_maps = (*this)[soinfo.Pid]
    if soinfo.LibPath == "" {
        soinfo.LibPath = fmt.Sprintf("UNNAMED_0x%x", soinfo.BaseAddr)
    }
    info := LibInfo{
        LibSize:  soinfo.LibSize,
        BaseAddr: soinfo.BaseAddr,
        LibPath:  soinfo.LibPath,
        EndAddr:  soinfo.BaseAddr + soinfo.LibSize,
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
            pid_maps[soinfo.LibPath] = base_list
        }
    } else {
        pid_maps[soinfo.LibPath] = []LibInfo{info}
    }
    (*this)[soinfo.Pid] = pid_maps
}

func (this *MapsHelper) GetOffset(pid uint32, addr uint64) (info string) {
    maps_lock.Lock()
    defer maps_lock.Unlock()
    pid_maps, ok := (*this)[pid]
    if !ok {
        // 暂时没有这个 pid 对应的 maps 信息
        return fmt.Sprintf("UNNKOWN + 0x%x", addr)
    }
    // 这里的计算是以库的每个段都是前后连续为前提的，暂时就这样
    // 但是实际上确实存在一些奇怪的操作
    // 1. 不连续的段
    // 2. 两个或者多个同名/同路径的库存在于maps中
    // 3. 其他...
    // 全部遍历是一种低效的写法，但是暂时没有更好的想法，就这样
    // 一定要优化那么应该在每次 pid_maps 变更的时候就进行排序 并按照基址大小插入
    var off_list []string = []string{}
    for lib_path, lib_infos := range pid_maps {
        for _, lib_info := range lib_infos {
            if addr >= lib_info.BaseAddr && addr < lib_info.EndAddr {
                offset := fmt.Sprintf("%s + 0x%x", lib_path, addr-lib_info.BaseAddr)
                off_list = append(off_list, offset)
            }
        }
    }
    if len(off_list) == 0 {
        return fmt.Sprintf("NOTFOUND + 0x%x", addr)
    }
    return strings.Join(off_list[:], ",")
}

// func (this *MapsHelper) toString() (s string) {
//     s = ""
//     s += fmt.Sprintln(*this)
//     return s
// }

var maps_helper = NewMapsHelper()
var maps_lock sync.Mutex

type SoInfoEvent struct {
    event_type EventType
    KEvent
    mconf *config.ModuleConfig
    // Pid      uint32
    // Tid      uint32
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
    maps_helper.UpdateMaps(this)
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
