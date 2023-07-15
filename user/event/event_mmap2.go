package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "stackplz/pkg/util"
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

// func (this *MapsHelper) UpdateMaps(soinfo *CommonEvent) {
//     // 拙劣的函数
//     maps_lock.Lock()
//     defer maps_lock.Unlock()
//     pid_maps, ok := (*this)[soinfo.Pid]
//     if !ok {
//         pid_maps = make(PidMaps)
//         (*this)[soinfo.Pid] = pid_maps
//     }
//     pid_maps = (*this)[soinfo.Pid]
//     if soinfo.LibPath == "" {
//         soinfo.LibPath = fmt.Sprintf("UNNAMED_0x%x", soinfo.BaseAddr)
//     }
//     info := LibInfo{
//         LibSize:  soinfo.LibSize,
//         BaseAddr: soinfo.BaseAddr,
//         LibPath:  soinfo.LibPath,
//         EndAddr:  soinfo.BaseAddr + soinfo.LibSize,
//     }
//     base_list, ok := pid_maps[soinfo.LibPath]
//     if ok {
//         // 注意基址列表去重 做成列表的原因是...
//         has_find := false
//         for _, info := range base_list {
//             if info.BaseAddr == info.BaseAddr {
//                 has_find = true
//                 break
//             }
//         }
//         if !has_find {
//             base_list = append(base_list, info)
//             pid_maps[soinfo.LibPath] = base_list
//         }
//     } else {
//         pid_maps[soinfo.LibPath] = []LibInfo{info}
//     }
//     (*this)[soinfo.Pid] = pid_maps
// }

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

type EventContext struct {
    Ts      uint64
    EventId uint32
    HostTid uint32
    HostPid uint32
    Tid     uint32
    Pid     uint32
    Uid     uint32
    Comm    [16]byte
    Argnum  uint8
    Padding [7]byte
}

// func (this *EventContext) GetUUID() string {
//     return fmt.Sprintf("%d_%d_%s", this.Pid, this.Tid, this.Comm)
// }

func (this *EventContext) String() (s string) {
    // 输出 event_context 解析结果 debug用
    s += fmt.Sprintf("event_id:%d ts:%d", this.EventId, this.Ts)
    s += fmt.Sprintf(", host_pid:%d, host_tid:%d", this.HostPid, this.HostTid)
    s += fmt.Sprintf(", uid:%d, pid:%d, tid:%d", this.Uid, this.Pid, this.Tid)
    s += fmt.Sprintf(", comm:%s, argnum:%d", util.B2STrim(this.Comm[:]), this.Argnum)
    return s
}

// type CommonEvent struct {
//     event_type EventType
//     CommonEvent
// }

type Mmap2Event struct {
    CommonEvent
    pid            uint32
    tid            uint32
    addr           uint64
    len            uint64
    pgoff          uint64
    maj            uint32
    min            uint32
    ino            uint64
    ino_generation uint64
    prot           uint32
    flags          uint32
    filename       string
    sample_id      []byte
}

// func (this *CommonEvent) Decode() (err error) {
//     panic("CommonEvent.Decode() not implemented yet")
// }

func (this *Mmap2Event) ReadIndex() (index uint8, err error) {
    err = binary.Read(this.buf, binary.LittleEndian, &index)
    return index, err
}

func (this *Mmap2Event) Decode() (err error) {
    if err = binary.Read(this.buf, binary.LittleEndian, &this.addr); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.len); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pgoff); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.maj); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.min); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.ino); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.ino_generation); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.prot); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.flags); err != nil {
        return err
    }
    var tmp = make([]byte, this.buf.Len())
    if err = binary.Read(this.buf, binary.LittleEndian, &tmp); err != nil {
        return err
    }
    this.filename = util.B2STrim(tmp)
    // maps_helper.UpdateMaps(this)
    return nil
}

func (this *Mmap2Event) String() string {
    var s string
    // s = fmt.Sprintf("[%s_%s]", this.GetUUID(), util.B2STrim(this.event_context.Comm[:]))
    s += fmt.Sprintf("[PERF_RECORD_MMAP2] %s Base:0x%x Size:0x%x Perm:0x%x Prot:0x%x <%s>", this.GetUUID(), this.addr, this.len, this.flags, this.prot, this.filename)
    return s
}

func (this *Mmap2Event) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.pid, this.tid)
}

func (this *Mmap2Event) ParseContext() (err error) {
    // this.logger.Printf("[Mmap2Event] RawSample len:%d\n", len(this.rec.RawSample))
    // if len(this.rec.RawSample) == 0 {
    //     return
    // }
    // this.logger.Printf("[Mmap2Event] RawSample\n" + util.HexDump(this.rec.RawSample, util.COLORRED))
    // 先把基础信息解析出来 后面再根据 eventid 进一步解析传递的参数
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.tid); err != nil {
        return err
    }
    return nil
}
