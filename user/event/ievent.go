package event

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "os"
    "stackplz/user/config"
    "stackplz/user/util"
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

func (this *CommonEvent) NewContextEvent() IEventStruct {
    event := &ContextEvent{CommonEvent: *this}
    err := event.ParseContext()
    if err != nil {
        panic(fmt.Sprintf("NewContextEvent.ParseContext() err:%v", err))
    }
    return event
}

func (this *CommonEvent) NewSyscallEvent(event IEventStruct) IEventStruct {
    p, ok := (event).(*ContextEvent)
    if !ok {
        panic("CommonEvent.NewSyscallEvent() cast to ContextEvent failed")
    }
    return p.NewSyscallEvent()
}
func (this *CommonEvent) NewUprobeEvent(event IEventStruct) IEventStruct {
    p, ok := (event).(*ContextEvent)
    if !ok {
        panic("CommonEvent.NewUprobeEvent() cast to ContextEvent failed")
    }
    return p.NewUprobeEvent()
}

func (this *CommonEvent) NewBrkEvent() IEventStruct {
    p := &ContextEvent{CommonEvent: *this}
    return p.NewBrkEvent()
}

func (this *CommonEvent) RecordType() uint32 {
    return this.rec.RecordType
}

func (this *CommonEvent) ParseEvent() (IEventStruct, error) {

    // 先根据 record 类型转为对应的 event
    // 然后对数据进行解析 为什么不给到 worker 处理呢
    // 这是因为当前的设计是基于 pid + tid 做了区分的
    // 每一个 pid + tid 组合都是单独的一个 worker
    // 另外也要注意 PERF_RECORD_MMAP2 事件和 syscall 等事件的区别
    // 前者无法预先设置过滤 后者可以

    var event IEventStruct
    switch this.rec.RecordType {
    case unix.PERF_RECORD_COMM:
        {
            event = this.NewCommEvent()
        }
    case unix.PERF_RECORD_MMAP2:
        {
            event = this.NewMmap2Event()
        }
    case unix.PERF_RECORD_EXIT:
        {
            event = this.NewExitEvent()
        }
    case unix.PERF_RECORD_FORK:
        {
            event = this.NewForkEvent()
        }
    case unix.PERF_RECORD_SAMPLE:
        {
            if this.mconf.BrkAddr != 0 {
                event = this.NewBrkEvent()
                break
            }
            // 先把需要的基础信息解析出来
            event = this.NewContextEvent()
            EventId := event.GetEventId()
            // 最后具体的 eventid 转换到具体的 event
            switch EventId {
            case SYSCALL_ENTER, SYSCALL_EXIT:
                {
                    // event = this.NewSyscallEvent(event)
                    switch (event).(type) {
                    case *SyscallEvent:
                        event = this.NewSyscallEvent(event)
                        break
                    case *NextSyscallEvent:
                        // 不用转应该也行吧..
                        event = (event).(*NextSyscallEvent)
                        err := event.ParseContext()
                        if err != nil {
                            panic(fmt.Sprintf("NewSyscallEvent.ParseContext() err:%v", err))
                        }
                        break
                    default:
                        panic("..")
                    }
                }
            case UPROBE_ENTER:
                {
                    event = this.NewUprobeEvent(event)
                }
            default:
                {
                    event = this
                    this.logger.Printf("CommonEvent.ParseEvent() unsupported EventId:%d\n", EventId)
                    this.logger.Printf("CommonEvent.ParseEvent() PERF_RECORD_SAMPLE RawSample:\n" + util.HexDump(this.rec.RawSample, util.COLORRED))
                    return nil, errors.New(fmt.Sprintf("PERF_RECORD_SAMPLE EventId is %d", EventId))
                }
            }
        }
    default:
        {
            return nil, errors.New(fmt.Sprintf("unsupported RecordType:%d", this.rec.RecordType))
        }
    }
    return event, nil
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
