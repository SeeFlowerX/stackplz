package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io/ioutil"
    "stackplz/user/util"
    "strings"
    "sync"
)

type LibInfo struct {
    BaseAddr uint64
    Off      uint64
    EndAddr  uint64
    LibPath  string
    LibName  string
}

func (this *LibInfo) ParseLib() {
    parts := strings.Split(this.LibPath, "/")
    this.LibName = parts[len(parts)-1]
}

var pid_list []uint32

type PidMaps map[string][]LibInfo

func (this *PidMaps) ToMapBuffer(pid uint32, del_old bool) string {
    // 把自身转换成 /proc/{pid}/maps 这样的内容

    return ""
}

type MapsHelper map[uint32]PidMaps

func NewMapsHelper() MapsHelper {
    helper := make(MapsHelper)
    return helper
}

func (this *MapsHelper) ParseMaps(pid uint32, del_old bool) error {
    filename := fmt.Sprintf("/proc/%d/maps", pid)
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        return fmt.Errorf("Error when opening file:%v", err)
    }
    var (
        seg_start  uint64
        seg_end    uint64
        permission string
        seg_offset uint64
        device     string
        inode      uint64
        seg_path   string
    )

    var pid_maps PidMaps
    if del_old {
        pid_maps = make(PidMaps)
        (*this)[pid] = pid_maps
    } else {
        pid_maps_x, ok := (*this)[pid]
        if !ok {
            pid_maps = make(PidMaps)
            (*this)[pid] = pid_maps
        } else {
            pid_maps = pid_maps_x
        }
    }
    for _, line := range strings.Split(string(content), "\n") {
        reader := strings.NewReader(line)
        n, err := fmt.Fscanf(reader, "%x-%x %s %x %s %d %s", &seg_start, &seg_end, &permission, &seg_offset, &device, &inode, &seg_path)
        if err == nil && n == 7 {
            if seg_path == "" {
                seg_path = fmt.Sprintf("UNNAMED_0x%x", seg_start)
            }
            new_info := LibInfo{
                BaseAddr: seg_start,
                Off:      seg_offset,
                EndAddr:  seg_end,
                LibPath:  seg_path,
            }
            new_info.ParseLib()

            base_list, ok := pid_maps[seg_path]
            if ok {
                // 注意基址列表去重 做成列表的原因是...
                has_find := false
                for _, info := range base_list {
                    if info.BaseAddr == new_info.BaseAddr {
                        has_find = true
                        break
                    }
                }
                if !has_find {
                    base_list = append(base_list, new_info)
                    pid_maps[seg_path] = base_list
                }
            } else {
                pid_maps[seg_path] = []LibInfo{new_info}
            }
        }
    }
    (*this)[pid] = pid_maps
    return nil
}

func (this *MapsHelper) UpdatePidList(pid uint32) {
    // uprobe syscall 初始化
    for _, v := range pid_list {
        if v == pid {
            return
        }
    }
    pid_list = append(pid_list, pid)
}
func (this *MapsHelper) UpdateMaps(event *Mmap2Event) {
    maps_lock.Lock()
    defer maps_lock.Unlock()
    // 只尝试解析存在于 pid_list 的
    exists := false
    for _, v := range pid_list {
        if v == event.Pid {
            exists = true
            break
        }
    }
    if !exists {
        return
    }
    // 遇到 mmap2 事件的时候都去尝试读取maps信息
    this.ParseMaps(event.Pid, true)
    pid_maps, ok := (*this)[event.Pid]
    if !ok {
        pid_maps = make(PidMaps)
        (*this)[event.Pid] = pid_maps
    }
    pid_maps = (*this)[event.Pid]

    if event.Filename == "" {
        event.Filename = fmt.Sprintf("UNNAMED_0x%x", event.Addr)
    }
    info := LibInfo{
        BaseAddr: event.Addr,
        Off:      event.Pgoff,
        EndAddr:  event.Addr + event.Len,
        LibPath:  event.Filename,
    }
    info.ParseLib()
    base_list, ok := pid_maps[event.Filename]
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
            pid_maps[event.Filename] = base_list
        }
    } else {
        pid_maps[event.Filename] = []LibInfo{info}
    }
    (*this)[event.Pid] = pid_maps
}

func (this *MapsHelper) GetOffset(pid uint32, addr uint64) (info string) {
    maps_lock.Lock()
    defer maps_lock.Unlock()
    pid_maps, ok := (*this)[pid]
    if !ok {
        // 一般不会进入这个分支
        err := this.ParseMaps(pid, false)
        if err != nil {
            return fmt.Sprintf("UNNKOWN + 0x%x", addr)
        }
        pid_maps, ok = (*this)[pid]
        if !ok {
            return fmt.Sprintf("UNNKOWN + 0x%x", addr)
        }
    }
    // 这里的计算是以库的每个段都是前后连续为前提的，暂时就这样
    // 但是实际上确实存在一些奇怪的操作
    // 1. 不连续的段
    // 2. 两个或者多个同名/同路径的库存在于maps中
    // 3. 其他...
    // 全部遍历是一种低效的写法，但是暂时没有更好的想法，就这样
    // 一定要优化那么应该在每次 pid_maps 变更的时候就进行排序 并按照基址大小插入
    var off_list []string = []string{}
    for _, lib_infos := range pid_maps {
        for _, lib_info := range lib_infos {
            if addr >= lib_info.BaseAddr && addr < lib_info.EndAddr {
                offset := lib_info.Off + (addr - lib_info.BaseAddr)
                off_list = append(off_list, fmt.Sprintf("%s + 0x%x", lib_info.LibName, offset))
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

type Mmap2Event struct {
    CommonEvent
    Pid            uint32
    Tid            uint32
    Addr           uint64
    Len            uint64
    Pgoff          uint64
    Maj            uint32
    Min            uint32
    Ino            uint64
    Ino_generation uint64
    Prot           uint32
    Flags          uint32
    Filename       string
    Sample_id      []byte
}

func (this *Mmap2Event) String() string {
    var s string
    s += fmt.Sprintf("[PERF_RECORD_MMAP2] %s Base:0x%x Size:0x%x Perm:0x%x Prot:0x%x <%s>", this.GetUUID(), this.Addr, this.Len, this.Flags, this.Prot, this.Filename)
    return s
}

func (this *Mmap2Event) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.Pid, this.Tid)
}

func (this *Mmap2Event) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    // 来源于自己的通通不管
    if this.mconf.SelfPid == this.Pid {
        return nil
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }

    if err = binary.Read(this.buf, binary.LittleEndian, &this.Addr); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Len); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pgoff); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Maj); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Min); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Ino); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Ino_generation); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Prot); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Flags); err != nil {
        return err
    }
    var tmp = make([]byte, this.buf.Len())
    if err = binary.Read(this.buf, binary.LittleEndian, &tmp); err != nil {
        return err
    }
    this.Filename = util.B2STrim(tmp)
    if this.mconf.Debug {
        s := fmt.Sprintf("[Mmap2Event] pid=%d tid=%d addr=0x%x len=0x%x pgoff=0x%x mag=%d min=%d ino=%d ino_generation=%d prot=0x%x flags=0x%x <%s>", this.Pid, this.Tid, this.Addr, this.Len, this.Pgoff, this.Maj, this.Min, this.Ino, this.Ino_generation, this.Prot, this.Flags, this.Filename)
        this.logger.Printf(s)
    }
    return nil
}

// func init() {
//     ddd := maps_helper.GetOffset(13117, 0x78cb40e658)
//     fmt.Println(ddd)
//     os.Exit(1)
// }
