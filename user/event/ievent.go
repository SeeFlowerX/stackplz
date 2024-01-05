package event

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "os"
    "stackplz/user/common"
    "stackplz/user/config"
    "stackplz/user/util"
    "sync"
    "syscall"
    "time"

    "github.com/cilium/ebpf/perf"
    "golang.org/x/sys/unix"
)

const (
    SYSCALL_ENTER uint32 = iota + 456
    SYSCALL_EXIT
    UPROBE_ENTER
    HW_BREAKPOINT
)

type IEventStruct interface {
    String() string
    Clone() IEventStruct
    GetUUID() string
    RecordType() uint32
    GetEventId() uint32
    DumpRecord() bool
    ParseEvent() (IEventStruct, error)
    ParseContext() error
    SetLogger(logger *log.Logger)
    SetConf(conf config.IConfig)
    SetRecord(rec perf.Record)
}

type CommonEvent struct {
    mconf  *config.ModuleConfig
    logger *log.Logger
    rec    perf.Record
    buf    *bytes.Buffer
}

func (this *CommonEvent) ParseArgStruct(buf *bytes.Buffer, arg config.ArgFormatter) string {
    if err := binary.Read(buf, binary.LittleEndian, arg); err != nil {
        this.logger.Printf("CommonEvent RawSample:\n%s", util.HexDump(this.rec.RawSample, util.COLORRED))
        time.Sleep(5 * 100 * time.Millisecond)
        panic(err)
    }
    return arg.Format()
}

func (this *CommonEvent) ParseArgStructHex(buf *bytes.Buffer, arg config.ArgHexFormatter) string {
    if err := binary.Read(buf, binary.LittleEndian, arg); err != nil {
        this.logger.Printf("CommonEvent RawSample:\n%s", util.HexDump(this.rec.RawSample, util.COLORRED))
        time.Sleep(5 * 100 * time.Millisecond)
        panic(err)
    }
    return arg.HexFormat()
}

func (this *CommonEvent) String() string {
    panic("CommonEvent String")
}

func (this *CommonEvent) GetUUID() string {
    panic("CommonEvent GetUUID")
}

func (this *CommonEvent) GetEventId() uint32 {
    panic("CommonEvent.GetEventId() not implemented yet")
}

func (this *CommonEvent) Clone() IEventStruct {
    event := new(CommonEvent)
    return event
}

func (this *CommonEvent) ParseContext() (err error) {
    if len(this.rec.RawSample) == 0 {
        this.logger.Printf("[CommonEvent] RawSample len:%d\n", len(this.rec.RawSample))
        return
    }
    this.logger.Printf("[CommonEvent] RawSample:%s\n", util.HexDump(this.rec.RawSample, util.COLORRED))
    return nil
}

func (this *CommonEvent) NewMmap2Event() IEventStruct {
    event := &Mmap2Event{CommonEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewMmap2Event.ParseContext() err:%v", err))
    }
    if event.Pid == uint32(os.Getpid()) {
        return nil
    }
    return event
}

func (this *CommonEvent) NewCommEvent() IEventStruct {
    event := &CommEvent{CommonEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewCommEvent.ParseContext() err:%v", err))
    }
    return event
}

func (this *CommonEvent) NewForkEvent() IEventStruct {
    event := &ForkEvent{CommonEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewForkEvent.ParseContext() err:%v", err))
    }
    return event
}

func (this *CommonEvent) NewExitEvent() IEventStruct {
    event := &ExitEvent{CommonEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewExitEvent.ParseContext() err:%v", err))
    }
    return event
}

func (this *CommonEvent) RecordType() uint32 {
    return this.rec.RecordType
}

func (this *CommonEvent) DumpRecord() bool {
    return this.mconf.DumpRecord(common.COMMON_EVENT, &this.rec)
}

func (this *CommonEvent) ParseEvent() (IEventStruct, error) {
    switch this.rec.RecordType {
    case unix.PERF_RECORD_COMM:
        return this.NewCommEvent(), nil
    case unix.PERF_RECORD_MMAP2:
        return this.NewMmap2Event(), nil
    case unix.PERF_RECORD_EXIT:
        return this.NewExitEvent(), nil
    case unix.PERF_RECORD_FORK:
        return this.NewForkEvent(), nil
    default:
        return nil, errors.New(fmt.Sprintf("unsupported RecordType:%d", this.rec.RecordType))
    }
}

func (this *CommonEvent) SetRecord(rec perf.Record) {
    this.rec = rec
}

func (this *CommonEvent) SetLogger(logger *log.Logger) {
    this.logger = logger
}

func (this *CommonEvent) SetConf(conf config.IConfig) {
    p, ok := (conf).(*config.ModuleConfig)
    if ok {
        this.mconf = p
    } else {
        panic("CommonEvent.SetConf() cast to ModuleConfig failed")
    }
}

var stopped_lock sync.Mutex
var stopped_pid_list map[uint32]bool = map[uint32]bool{}

func AddStopped(pid uint32) {
    stopped_lock.Lock()
    defer stopped_lock.Unlock()
    stopped_pid_list[pid] = true
}

func DelStopped(pid uint32) {
    stopped_lock.Lock()
    defer stopped_lock.Unlock()
    delete(stopped_pid_list, pid)
}

func LetItRun() {
    fmt.Printf("------LetItRun------\n")
    for stopped_pid := range stopped_pid_list {
        err := syscall.Kill(int(stopped_pid), syscall.SIGCONT)
        if err != nil {
            if err == syscall.ESRCH {
                fmt.Printf("No such process -> %d\n", stopped_pid)
                DelStopped(stopped_pid)
            } else {
                fmt.Printf("LetItRun err:%v\n", err)
                DelStopped(stopped_pid)
            }
        }
        fmt.Printf("Let %d run\n", stopped_pid)
    }
}
