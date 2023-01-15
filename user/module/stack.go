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

type MStack struct {
    Module
    mconf             *config.ModuleConfig
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]event.IEventStruct
    eventMaps         []*ebpf.Map

    hookBpfFile        string
    stack_uprobe_hook  bool
    stack_syscall_hook bool
}

func (this *MStack) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
    this.Module.Init(ctx, logger, conf)
    p, ok := (conf).(*config.ModuleConfig)
    if ok {
        this.mconf = p
    }
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
    this.hookBpfFile = "stack.o"
    return nil
}

func (this *MStack) GetConf() string {
    return this.mconf.Info()
}

func (this *MStack) setupManager() error {
    if this.mconf.Debug {
        this.logger.Printf("Symbol:%s Library:%s Offset:0x%x", this.mconf.UprobeConf.Symbol, this.mconf.UprobeConf.Library, this.mconf.UprobeConf.Offset)
    }
    this.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "uprobe/stack",
                EbpfFuncName:     "probe_stack",
                AttachToFuncName: this.mconf.UprobeConf.Symbol,
                BinaryPath:       this.mconf.UprobeConf.Library,
                UprobeOffset:     this.mconf.UprobeConf.Offset,
                // 这样每个hook点都使用独立的程序
                // UID: util.RandStringBytes(8),
            },
            {
                Section:      "raw_tracepoint/sys_enter",
                EbpfFuncName: "raw_syscalls_sys_enter",
            },
            {
                Section:      "raw_tracepoint/sys_exit",
                EbpfFuncName: "raw_syscalls_sys_exit",
            },
        },

        Maps: []*manager.Map{
            {
                Name: "stack_events",
            },
            {
                Name: "syscall_events",
            },
        },
    }
    return nil
}

func (this *MStack) setupManagersUprobe() error {
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

func (this *MStack) Start() error {
    return this.start()
}

func (this *MStack) Clone() IModule {
    mod := new(MStack)
    mod.name = this.name
    mod.mType = this.mType
    return mod
}

func (this *MStack) start() error {
    // 保不齐什么时候写出bug了 这里再次检查uid
    if this.mconf.Uid == 0 {
        return fmt.Errorf("uid is 0, %s", this.GetConf())
    }
    // 要注意 一部分选项是通用的
    // 常规ELF uprobe hook 和 syscall hook 要分别设置

    // 先判断有是只hook其中一个 还是两个都要
    this.stack_uprobe_hook = false
    this.stack_syscall_hook = false
    if this.mconf.UprobeConf.IsEnable() {
        this.stack_uprobe_hook = true
    }
    if this.mconf.SyscallConf.IsEnable() {
        this.stack_syscall_hook = true
    }
    if !this.stack_uprobe_hook && !this.stack_uprobe_hook {
        return errors.New("hook nothing")
    }

    // 初始化uprobe相关设置
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
    filter := this.mconf.GetFilter()
    filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)

    // 加载map信息，设置eventFuncMaps，给不同的事件指定处理事件数据的函数
    err = this.initDecodeFun()
    if err != nil {
        return err
    }

    return nil
}

func (this *MStack) initDecodeFun() error {
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

func (this *MStack) Events() []*ebpf.Map {
    return this.eventMaps
}

func (this *MStack) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
    fun, found := this.eventFuncMaps[em]
    return fun, found
}

func (this *MStack) Dispatcher(e event.IEventStruct) {
    // 事件类型指定为 EventTypeModuleData 直接使用当前方法处理
    // 如果需要多处联动收集信息 比如做统计之类的 那么使用 EventTypeEventProcessor 类型 并设计处理模式更合理

    e.(*event.HookDataEvent).RegName = this.sconf.RegName
    e.(*event.HookDataEvent).ShowRegs = this.sconf.ShowRegs
    e.(*event.HookDataEvent).UnwindStack = this.sconf.UnwindStack
    this.logger.Println(e.(*event.HookDataEvent).String())
}

func init() {
    mod := &MStack{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
