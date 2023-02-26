package event

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "stackplz/pkg/util"
    "stackplz/user/config"
    "strings"
)

type Timespec struct {
    TvSec  uint64 /* seconds */
    TvNsec uint64 /* nanoseconds */
}

func (this *Timespec) String() string {
    return fmt.Sprintf("seconds=%d,nanoseconds=%d", this.TvSec, this.TvNsec)
}

type SyscallEvent struct {
    event_type   EventType
    mconf        *config.ModuleConfig
    UUID         string
    Stackinfo    string
    RegsBuffer   RegsBuf
    UnwindBuffer UnwindBuf
    pid          uint32
    tid          uint32
    mtype        uint32
    syscall_id   uint32
    lr           uint64
    sp           uint64
    pc           uint64
    ret          uint64
    arg_index    uint64
    args         [6]uint64
    comm         [16]byte
    arg_str      [1024]byte
}

func (this *SyscallEvent) SetConf(conf config.IConfig) {
    // 原生指针转换 conf 是指针的时候 但不能是 interface
    // this.mconf = (*config.ModuleConfig)(unsafe.Pointer(conf))
    p, ok := (conf).(*config.ModuleConfig)
    if ok {
        this.mconf = p
    } else {
        panic("SyscallEvent.SetConf() cast to ModuleConfig failed")
    }
}

func (this *SyscallEvent) Decode(payload []byte, unwind_stack, regs bool) (err error) {
    buf := bytes.NewBuffer(payload)
    if err = binary.Read(buf, binary.LittleEndian, &this.pid); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.tid); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.mtype); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.syscall_id); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.lr); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.sp); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.pc); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.ret); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.arg_index); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.args); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.comm); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.arg_str); err != nil {
        return
    }
    return nil
}

func (this *SyscallEvent) GetUUID() string {
    return fmt.Sprintf("%d|%d|%s", this.pid, this.tid, util.B2STrim(this.comm[:]))
}

func (this *SyscallEvent) String() string {
    conf := this.mconf
    nr := this.mconf.SysCallConf.SysTable.ReadNR(this.syscall_id)
    var base_str string
    if conf.Debug {
        base_str = fmt.Sprintf("[%s] type:%d nr:%s", this.GetUUID(), this.mtype, nr)
    } else {
        base_str = fmt.Sprintf("[%s] nr:%s", this.GetUUID(), nr)
    }
    // type 和数据发送的顺序相关
    switch this.mtype {
    case 1:
        // --getlr 和 --getpc 建议只使用其中一个
        if conf.GetLR {
            info, err := this.ParseLR()
            if err != nil {
                return fmt.Sprintf("ParseLR err:%v\n", err)
            }
            return fmt.Sprintf("%s LR:0x%x Info:\n%s\n", base_str, this.lr, info)
        }
        if conf.GetPC {
            info, err := this.ParsePC()
            if err != nil {
                return fmt.Sprintf("ParsePC err:%v\n", err)
            }
            return fmt.Sprintf("%s PC:0x%x Info:\n%s\n", base_str, this.pc, info)
        }
    case 2:
        var arg_str string
        if nr == "nanosleep" {
            var spec Timespec
            t_buf := bytes.NewBuffer(this.arg_str[:])
            if err := binary.Read(t_buf, binary.LittleEndian, &spec); err != nil {
                return fmt.Sprintf("%s", err)
            }
            arg_str = spec.String()
        } else {
            arg_str = strings.SplitN(string(bytes.Trim(this.arg_str[:], "\x00")), "\x00", 2)[0]
        }
        return fmt.Sprintf("%s arg_index:%d arg_str:%s", base_str, this.arg_index, strings.TrimSpace(arg_str))
    case 3:
        return fmt.Sprintf("%s %s", base_str, this.ReadArgs())
    case 4:
        arg_str := strings.SplitN(string(bytes.Trim(this.arg_str[:], "\x00")), "\x00", 2)[0]
        return fmt.Sprintf("%s arg_index:%d arg_ret_str:%s", base_str, this.arg_index, strings.TrimSpace(arg_str))
    case 5:
        return fmt.Sprintf("%s ret:0x%x", base_str, this.ret)
    case 6:
        arg_str := strings.SplitN(string(bytes.Trim(this.arg_str[:], "\x00")), "\x00", 2)[0]
        return fmt.Sprintf("%s arg_index:%d arg_after_str:%s", base_str, this.arg_index, strings.TrimSpace(arg_str))
    }
    return base_str
}

func (this *SyscallEvent) ParseLR() (string, error) {
    info := "UNKNOWN"
    // 直接读取maps信息 计算lr在什么地方 定位syscall调用也就一目了然了
    filename := fmt.Sprintf("/proc/%d/maps", this.pid)
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        return info, fmt.Errorf("Error when opening file:%v", err)
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
    for _, line := range strings.Split(string(content), "\n") {
        reader := strings.NewReader(line)
        n, err := fmt.Fscanf(reader, "%x-%x %s %x %s %d %s", &seg_start, &seg_end, &permission, &seg_offset, &device, &inode, &seg_path)
        if err == nil && n == 7 {
            if this.lr >= seg_start && this.lr < seg_end {
                offset := seg_offset + (this.lr - seg_start)
                info = fmt.Sprintf("%s + 0x%x", seg_path, offset)
                break
            }
        }
    }
    return info, err
}

func (this *SyscallEvent) ParsePC() (string, error) {
    info := "UNKNOWN"
    // 直接读取maps信息 计算pc在什么地方 定位syscall调用也就一目了然了
    filename := fmt.Sprintf("/proc/%d/maps", this.pid)
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        return info, fmt.Errorf("Error when opening file:%v", err)
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
    for _, line := range strings.Split(string(content), "\n") {
        reader := strings.NewReader(line)
        n, err := fmt.Fscanf(reader, "%x-%x %s %x %s %d %s", &seg_start, &seg_end, &permission, &seg_offset, &device, &inode, &seg_path)
        if err == nil && n == 7 {
            if this.pc >= seg_start && this.pc < seg_end {
                offset := seg_offset + (this.pc - seg_start)
                info = fmt.Sprintf("%s + 0x%x", seg_path, offset)
                break
            }
        }
    }
    return info, err
}

func (this *SyscallEvent) ReadArgs() string {
    config := this.mconf.SysCallConf.SysTable[fmt.Sprintf("%d", this.syscall_id)]
    regs := make(map[string]string)
    for i := 0; i < int(config.Count); i++ {
        regs[fmt.Sprintf("x%d", i)] = fmt.Sprintf("0x%x", this.args[i])
    }
    regs["lr"] = fmt.Sprintf("0x%x", this.lr)
    regs["sp"] = fmt.Sprintf("0x%x", this.sp)
    regs["pc"] = fmt.Sprintf("0x%x", this.pc)
    regs_info, err := json.Marshal(regs)
    if err != nil {
        regs_info = make([]byte, 0)
    }
    return string(regs_info)
}

func (this *SyscallEvent) EventType() EventType {
    return this.event_type
}

func (this *SyscallEvent) Clone() IEventStruct {
    event := new(SyscallEvent)
    event.event_type = EventTypeSysCallData
    return event
}
