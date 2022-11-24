package module

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "log"
    "math"
    "path/filepath"
    "stackplz/assets"
    "stackplz/user/config"
    "stackplz/user/event"
    "unsafe"

    "github.com/cilium/ebpf"
    manager "github.com/ehids/ebpfmanager"
    "golang.org/x/sys/unix"
)

type MRawSyscallsTracepoint struct {
    Module
    sysConf           *config.SyscallConfig
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]event.IEventStruct
    eventMaps         []*ebpf.Map

    hookBpfFile string
}

func (this *MRawSyscallsTracepoint) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
    this.Module.Init(ctx, logger, conf)
    p, ok := (conf).(*config.SyscallConfig)
    if ok {
        this.sysConf = p
    }
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
    this.hookBpfFile = "raw_syscalls.o"
    return nil
}

func (this *MRawSyscallsTracepoint) setupManager() error {
    if this.sysConf.Debug {
        this.logger.Printf("NR:%d", this.sysConf.NR)
    }
    this.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:      "tracepoint/raw_syscalls/sys_enter",
                EbpfFuncName: "raw_syscalls_sys_enter",
            },
        },

        Maps: []*manager.Map{
            {
                Name: "syscall_events",
            },
        },
    }
    return nil
}

func (this *MRawSyscallsTracepoint) setupManagersUprobe() error {
    err := this.setupManager()
    if err != nil {
        return err
    }

    this.bpfManagerOptions = manager.Options{
        DefaultKProbeMaxActive: 512,

        VerifierOptions: ebpf.CollectionOptions{
            Programs: ebpf.ProgramOptions{
                LogSize: 2097152,
            },
        },

        RLimit: &unix.Rlimit{
            Cur: math.MaxUint64,
            Max: math.MaxUint64,
        },
    }

    // 可以使用 manager.ConstantEditor 这样的方法替换常量，但是相关特性在4.x内核上不支持
    // 本项目处理是直接修改预设的二进制数据

    return nil
}

func (this *MRawSyscallsTracepoint) Start() error {
    return this.start()
}

func (this *MRawSyscallsTracepoint) Clone() IModule {
    mod := new(MRawSyscallsTracepoint)
    mod.name = this.name
    mod.mType = this.mType
    return mod
}

func (this *MRawSyscallsTracepoint) GetConf() string {
    return this.sysConf.Info()
}

func (this *MRawSyscallsTracepoint) start() error {
    // 保不齐什么时候写出bug了 这里再次检查uid
    if this.sysConf.Uid == 0 {
        return fmt.Errorf("uid is 0, %s", this.GetConf())
    }
    // 初始化Uprobe相关设置
    err := this.setupManagersUprobe()
    if err != nil {
        return err
    }

    // 从assets中获取eBPF程序的二进制数据
    var bpfFileName = filepath.Join("user/bytecode", this.hookBpfFile)
    // this.logger.Printf("%s\tBPF bytecode filename:%s\n", this.Name(), bpfFileName)
    byteBuf, err := assets.Asset(bpfFileName)

    // // 通过直接替换二进制数据实现uid过滤
    // target_uid_buf := []byte{0xAA, 0xCC, 0xBB, 0xAA}
    // uid_buf := util.IntToBytes(int(this.sconf.Uid))
    // byteBuf = bytes.Replace(byteBuf, target_uid_buf, uid_buf, 3)
    // // 替换 pid
    // if this.sconf.Pid > 0 {
    //     pid_buf := util.UIntToBytes(uint32(this.sconf.Pid))
    //     byteBuf = bytes.Replace(byteBuf, []byte{0x99, 0xCC, 0xBB, 0xAA}, pid_buf, 3)
    //     byteBuf = bytes.Replace(byteBuf, []byte{0x11, 0xCC, 0xBB, 0xAA}, []byte{0x00, 0x00, 0x00, 0x00}, 3)
    // }
    // // 替换 NR
    // target_nr_buf := []byte{0x77, 0xCC, 0xBB, 0xAA}
    // nr_buf := util.IntToBytes(int(this.sysConf.NR))
    // byteBuf = bytes.Replace(byteBuf, target_nr_buf, nr_buf, 3)

    if err != nil {
        return fmt.Errorf("%s\tcouldn't find asset %v .", this.Name(), err)
    }

    // 初始化 bpfManager
    if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
        return fmt.Errorf("couldn't init manager %v", err)
    }

    // 启动 bpfManager
    if err = this.bpfManager.Start(); err != nil {
        return fmt.Errorf("couldn't start bootstrap manager %v .", err)
    }

    // 更新进程过滤设置
    filterMap, found, err := this.bpfManager.GetMap("filter_map")
    if !found {
        return errors.New("cannot find filter_map")
    }
    filter_key := 0
    filter := this.sysConf.GetFilter()
    filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)

    // 加载map信息，设置eventFuncMaps，给不同的事件指定处理事件数据的函数
    err = this.initDecodeFun()
    if err != nil {
        return err
    }

    return nil
}

func (this *MRawSyscallsTracepoint) initDecodeFun() error {
    SyscallEventsMap, found, err := this.bpfManager.GetMap("syscall_events")
    if err != nil {
        return err
    }
    if !found {
        return errors.New("cant found map:syscall_events")
    }
    this.eventMaps = append(this.eventMaps, SyscallEventsMap)
    hookEvent := &event.SyscallDataEvent{}
    this.eventFuncMaps[SyscallEventsMap] = hookEvent

    return nil
}

func (this *MRawSyscallsTracepoint) Events() []*ebpf.Map {
    return this.eventMaps
}

func (this *MRawSyscallsTracepoint) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
    fun, found := this.eventFuncMaps[em]
    return fun, found
}

func (this *MRawSyscallsTracepoint) Dispatcher(e event.IEventStruct) {
    // 事件类型指定为 EventTypeModuleData 直接使用当前方法处理
    // 如果需要多处联动收集信息 比如做统计之类的 那么使用 EventTypeEventProcessor 类型 并设计处理模式更合理

    e.(*event.SyscallDataEvent).ShowRegs = this.sconf.ShowRegs
    e.(*event.SyscallDataEvent).UnwindStack = this.sconf.UnwindStack
    this.logger.Println(e.(*event.SyscallDataEvent).String())
}

func init() {
    mod := &MRawSyscallsTracepoint{}
    mod.name = MODULE_NAME_SYSCALL
    mod.mType = PROBE_TYPE_TRACEPOINT
    Register(mod)
}
