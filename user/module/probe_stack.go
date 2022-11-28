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

type MStackProbe struct {
    Module
    probeConf         *config.ProbeConfig
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]event.IEventStruct
    eventMaps         []*ebpf.Map

    hookBpfFile string
}

func (this *MStackProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
    this.Module.Init(ctx, logger, conf)
    p, ok := (conf).(*config.ProbeConfig)
    if ok {
        this.probeConf = p
    }
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
    this.hookBpfFile = "stack.o"
    return nil
}

func (this *MStackProbe) GetConf() string {
    return this.probeConf.Info()
}

func (this *MStackProbe) setupManager() error {
    if this.probeConf.Debug {
        this.logger.Printf("Symbol:%s Library:%s Offset:0x%x", this.probeConf.Symbol, this.probeConf.Library, this.probeConf.Offset)
    }
    this.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "uprobe/stack",
                EbpfFuncName:     "probe_stack",
                AttachToFuncName: this.probeConf.Symbol,
                BinaryPath:       this.probeConf.Library,
                UprobeOffset:     this.probeConf.Offset,
                // 这样每个hook点都使用独立的程序
                // UID: util.RandStringBytes(8),
            },
        },

        Maps: []*manager.Map{
            {
                Name: "stack_events",
            },
        },
    }
    return nil
}

func (this *MStackProbe) setupManagersUprobe() error {
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

func (this *MStackProbe) Start() error {
    return this.start()
}

func (this *MStackProbe) Clone() IModule {
    mod := new(MStackProbe)
    mod.name = this.name
    mod.mType = this.mType
    return mod
}

func (this *MStackProbe) start() error {
    // 保不齐什么时候写出bug了 这里再次检查uid
    if this.probeConf.Uid == 0 {
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
    filter := this.probeConf.GetFilter()
    filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)

    // 加载map信息，设置eventFuncMaps，给不同的事件指定处理事件数据的函数
    err = this.initDecodeFun()
    if err != nil {
        return err
    }

    return nil
}

func (this *MStackProbe) initDecodeFun() error {
    StackEventsMap, found, err := this.bpfManager.GetMap("stack_events")
    if err != nil {
        return err
    }
    if !found {
        return errors.New("cant found map:stack_events")
    }
    this.eventMaps = append(this.eventMaps, StackEventsMap)
    hookEvent := &event.HookDataEvent{}
    this.eventFuncMaps[StackEventsMap] = hookEvent

    return nil
}

func (this *MStackProbe) Events() []*ebpf.Map {
    return this.eventMaps
}

func (this *MStackProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
    fun, found := this.eventFuncMaps[em]
    return fun, found
}

func (this *MStackProbe) Dispatcher(e event.IEventStruct) {
    // 事件类型指定为 EventTypeModuleData 直接使用当前方法处理
    // 如果需要多处联动收集信息 比如做统计之类的 那么使用 EventTypeEventProcessor 类型 并设计处理模式更合理

    e.(*event.HookDataEvent).RegName = this.sconf.RegName
    e.(*event.HookDataEvent).ShowRegs = this.sconf.ShowRegs
    e.(*event.HookDataEvent).UnwindStack = this.sconf.UnwindStack
    this.logger.Println(e.(*event.HookDataEvent).String())
}

func init() {
    mod := &MStackProbe{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
