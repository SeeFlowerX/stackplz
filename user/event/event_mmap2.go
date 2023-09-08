package event

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "stackplz/user/config"
    "stackplz/user/util"
    "strings"
    "sync"

    "golang.org/x/exp/slices"
)

type LibInfo struct {
    BaseAddr uint64
    Off      uint64
    EndAddr  uint64
    LibPath  string
    LibName  string
}

func (this *LibInfo) Clone() LibInfo {
    info := LibInfo{}
    info.BaseAddr = this.BaseAddr
    info.Off = this.Off
    info.EndAddr = this.EndAddr
    info.LibPath = this.LibPath
    info.LibName = this.LibName
    return info
}

func (this *LibInfo) ParseLib() {
    parts := strings.Split(this.LibPath, "/")
    this.LibName = parts[len(parts)-1]
}

var pid_list []uint32

type ProcMaps map[string][]LibInfo

func (this *MapsHelper) GetRegion(pid_maps *ProcMaps, addr uint64) *LibInfo {
    var region LibInfo
    for _, lib_infos := range *pid_maps {
        for _, lib_info := range lib_infos {
            // this.logger.Printf("[lib_info] start:0x%x end:0x%x name:%s\n", lib_info.BaseAddr, lib_info.EndAddr, lib_info.LibName)
            if addr >= lib_info.BaseAddr && addr < lib_info.EndAddr {
                region = lib_info
            }
        }
    }
    return &region
}

func (this *MapsHelper) GetRegionInfo(pid_maps *ProcMaps, addr uint64) string {
    var info string = fmt.Sprintf("0x%x <unknown>", addr)
    for _, lib_infos := range *pid_maps {
        for _, lib_info := range lib_infos {
            if addr >= lib_info.BaseAddr && addr < lib_info.EndAddr {
                offset := lib_info.Off + (addr - lib_info.BaseAddr)
                info = fmt.Sprintf("0x%x <%s + 0x%x>", addr, lib_info.LibName, offset)
            }
        }
    }
    return info
}

func (this *ProcMaps) Clone() ProcMaps {
    maps := ProcMaps{}
    for key, value := range *this {
        var infos []LibInfo
        for _, ori_info := range value {
            infos = append(infos, ori_info)
        }
        maps[key] = infos
    }
    return maps
}

type MapsHelper struct {
    logger           *log.Logger
    pid_maps         map[uint32]*ProcMaps
    child_parent_map map[uint32]uint32
}

func NewMapsHelper() *MapsHelper {
    helper := &MapsHelper{}
    helper.InitMap()
    return helper
}

func (this *MapsHelper) SetLogger(logger *log.Logger) {
    this.logger = logger
}

func (this *MapsHelper) InitMap() {
    this.pid_maps = make(map[uint32]*ProcMaps)
    this.child_parent_map = make(map[uint32]uint32)
}
func (this *MapsHelper) FindLib(pid uint32) (ProcMaps, error) {
    maps_lock.Lock()
    defer maps_lock.Unlock()
    pid_maps, ok := this.pid_maps[pid]
    if !ok {
        err := this.ParseMaps(pid, false)
        if err != nil {
            return nil, err
        }
        pid_maps, ok = this.pid_maps[pid]
        if !ok {
            return nil, errors.New("get ProcMaps by pid failed")
        }
    }
    return pid_maps.Clone(), nil
}

func FindLibPaths(pid uint32) ([]string, error) {
    var search_paths []string
    pid_maps, err := maps_helper.FindLib(pid)
    if err != nil {
        return search_paths, err
    }
    for seg_path, _ := range pid_maps {
        if strings.HasPrefix(seg_path, "/") && strings.HasSuffix(seg_path, ".so") {
            items := strings.Split(seg_path, "/")
            lib_search_path := strings.Join(items[:len(items)-1], "/")
            if !slices.Contains(search_paths, lib_search_path) {
                search_paths = append(search_paths, lib_search_path)
            }
        }
    }
    return search_paths, nil
}

func (this *MapsHelper) UpdateForkEvent(event *ForkEvent) {
    // 根据日志实际的记录结果 fork 的 pid ppid 存在相同的情况 why
    parent_pid, ok := this.child_parent_map[event.Pid]
    if !ok {
        this.child_parent_map[event.Pid] = event.Ppid
        // 为了便于后续能够快速查找进程的maps
        // 出现fork事件的时候 把父进程已经收集到的 maps 信息也复制一份
        // 最开始想设计为需要计算的时候 查找父进程 再去解析偏移 但是考虑到fork产生的子进程可能会产生新的操作 这样不合理
        if event.Pid != event.Ppid {
            this.CloneMaps(event.Pid, event.Ppid)
        }
    } else {
        // 大多数情况下应该是不会到这个分支的 除非是进程id不够用了
        // 例如 A 产生 B B 产生 C A结束 C 产生 D 那么这个时候 D 被分配的pid可能是之前A的pid（应该是有这个概率的
        if parent_pid != event.Ppid {
            // 本次所产生的子进程的父进程 与原本记录的父进程不一致
            // 那么更新此次的子进程的父进程
            this.child_parent_map[event.Pid] = event.Ppid
        }
    }
}

func (this *MapsHelper) CloneMaps(pid, parent_pid uint32) (err error) {
    // 为子进程复制一份maps信息
    maps_lock.Lock()
    defer maps_lock.Unlock()
    pid_maps, ok := this.pid_maps[parent_pid]
    if !ok {
        // 在当前维护的maps中不存在父进程的 比如是在进程运行过程中hook的
        // 那么尝试去读取父进程的maps
        err = this.ParseMaps(parent_pid, false)
        if err != nil {
            // 应该不会走到这个分支
            return err
        }
        pid_maps, ok = this.pid_maps[parent_pid]
        if !ok {
            // ParseMaps 成功的情况下应该不会到这个分支
            return errors.New(fmt.Sprintf("ParseMaps success, but get pid_maps failed by child:%d parent:%d", pid, parent_pid))
        }
    }
    copied_maps := pid_maps.Clone()
    this.pid_maps[pid] = &copied_maps
    return nil
}

func (this *MapsHelper) GetStack(pid uint32, ubuf *UnwindBuf) (info string, err error) {
    // 当直接读取 maps 文件失败的时候 就采用这个方案获取堆栈
    maps_lock.Lock()
    defer maps_lock.Unlock()
    // 首先尝试获取 pid 对应的 maps 信息
    pid_maps, ok := this.pid_maps[pid]
    if !ok {
        return "", errors.New(fmt.Sprintf("[GetStack] get pid_maps failed by pid:%d", pid))
    }

    // perf_output_sample_ustack dump获取到的栈空间数据 起始地址就是 sp
    stack_buf := bytes.NewReader(ubuf.Data[:])
    fp := ubuf.Regs[config.REG_ARM64_X29]
    // lr := ubuf.Regs[config.REG_ARM64_LR]
    sp := ubuf.Regs[config.REG_ARM64_SP]
    pc := ubuf.Regs[config.REG_ARM64_PC]
    // 栈解析结果
    // var stack_arr []uint64
    var stack_infos []string
    // stack_arr = append(stack_arr, pc)
    stack_infos = append(stack_infos, this.GetRegionInfo(pid_maps, pc))
    // 奇怪 这里竟然没有 sp 所在的map信息
    // sp_region := this.GetRegion(pid_maps, sp)
    // this.logger.Printf("start:0x%x end:0x%x name:%s\n", sp_region.BaseAddr, sp_region.EndAddr, sp_region.LibName)
    // this.logger.Printf("pc:0x%x fp:0x%x sp:0x%x\n", pc, fp, sp)
    for i := 0; i < 20; i++ {
        // if fp < sp || fp < sp_region.BaseAddr || fp > sp_region.EndAddr {
        //     break
        // }
        if fp < sp {
            break
        }
        fp_offset := fp - sp
        stack_buf.Seek(int64(fp_offset), io.SeekStart)
        var next_fp uint64
        err = binary.Read(stack_buf, binary.LittleEndian, &next_fp)
        if err != nil {
            this.logger.Printf("read next_fp at offset:0x%x failed\n", fp_offset)
            break
        }
        var next_lr uint64
        err = binary.Read(stack_buf, binary.LittleEndian, &next_lr)
        if err != nil {
            this.logger.Printf("read next_lr at offset:0x%x failed\n", fp_offset+uint64(binary.Size(next_fp)))
            break
        }
        fp = next_fp
        if next_lr != 0 {
            stack_infos = append(stack_infos, this.GetRegionInfo(pid_maps, next_lr))
        }
    }
    backtrace := fmt.Sprintf("\t%s", strings.Join(stack_infos, "\n\t"))
    return backtrace, nil
    // return this.GetOffset(pid, addr), nil
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

    if del_old {
        this.pid_maps[pid] = &ProcMaps{}
    } else {
        _, ok := this.pid_maps[pid]
        if !ok {
            this.pid_maps[pid] = &ProcMaps{}
        }
    }
    pid_maps := this.pid_maps[pid]
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

            base_list, ok := (*pid_maps)[seg_path]
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
                    (*pid_maps)[seg_path] = base_list
                }
            } else {
                (*pid_maps)[seg_path] = []LibInfo{new_info}
            }
        }
    }
    this.pid_maps[pid] = pid_maps
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
    if !slices.Contains(pid_list, event.Pid) {
        return
    }
    // 遇到 mmap2 事件的时候都去尝试读取maps信息
    this.ParseMaps(event.Pid, false)
    pid_maps, ok := this.pid_maps[event.Pid]
    if !ok {
        this.pid_maps[event.Pid] = &ProcMaps{}
    }
    pid_maps = this.pid_maps[event.Pid]

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
    base_list, ok := (*pid_maps)[event.Filename]
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
            (*pid_maps)[event.Filename] = base_list
        }
    } else {
        (*pid_maps)[event.Filename] = []LibInfo{info}
    }
    // 这一句应该不用了？
    this.pid_maps[event.Pid] = pid_maps
}

func (this *MapsHelper) GetOffset(pid uint32, addr uint64) (info string) {
    maps_lock.Lock()
    defer maps_lock.Unlock()
    pid_maps, ok := this.pid_maps[pid]
    if !ok {
        // 一般不会进入这个分支
        err := this.ParseMaps(pid, false)
        if err != nil {
            return fmt.Sprintf("UNNKOWN + 0x%x", addr)
        }
        pid_maps, ok = this.pid_maps[pid]
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
    for _, lib_infos := range *pid_maps {
        for _, lib_info := range lib_infos {
            if addr >= lib_info.BaseAddr && addr < lib_info.EndAddr {
                offset := lib_info.Off + (addr - lib_info.BaseAddr)
                off_info := fmt.Sprintf("%s + 0x%x", lib_info.LibName, offset)
                if !slices.Contains(off_list, off_info) {
                    off_list = append(off_list, off_info)
                }
            }
        }
    }
    if len(off_list) == 0 {
        return fmt.Sprintf("NOTFOUND + 0x%x", addr)
    }
    return strings.Join(off_list[:], ",")
}

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
    maps_helper.UpdateMaps(this)
    return nil
}

func FindLibInMaps(pid uint32, brk_lib string) (LibInfo, error) {
    var info LibInfo
    pid_maps, err := maps_helper.FindLib(pid)
    if err != nil {
        return info, err
    }
    for _, lib_infos := range pid_maps {
        for _, lib_info := range lib_infos {
            if brk_lib == lib_info.LibPath {
                info = lib_info
                break
            }
            if brk_lib == lib_info.LibName {
                info = lib_info
                break
            }
        }
    }
    return info, err
}

// func init() {
//     ddd := maps_helper.GetOffset(13117, 0x78cb40e658)
//     fmt.Println(ddd)
//     os.Exit(1)
// }
