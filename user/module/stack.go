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
        if this.stack_uprobe_hook {
            this.logger.Printf("Symbol:%s Library:%s Offset:0x%x", this.mconf.UprobeConf.Symbol, this.mconf.UprobeConf.Library, this.mconf.UprobeConf.Offset)
        }
        if this.stack_syscall_hook {
            this.logger.Printf("Syscall:%s", this.mconf.SyscallConf.GetNR())
        }
    }
    if this.stack_uprobe_hook && this.stack_syscall_hook {
        this.bpfManager = &manager.Manager{
            Probes: []*manager.Probe{
                {
                    Section:          "uprobe/soinfo",
                    EbpfFuncName:     "probe_soinfo",
                    AttachToFuncName: "__dl__ZN6soinfo17call_constructorsEv",
                    BinaryPath:       "/apex/com.android.runtime/bin/linker64",
                    UprobeOffset:     0,
                },
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
                    Name: "soinfo_events",
                },
                {
                    Name: "stack_events",
                },
                {
                    Name: "syscall_events",
                },
            },
        }
    }
    if this.stack_uprobe_hook {
        this.bpfManager = &manager.Manager{
            Probes: []*manager.Probe{
                {
                    Section:          "uprobe/soinfo",
                    EbpfFuncName:     "probe_soinfo",
                    AttachToFuncName: "__dl__ZN6soinfo17call_constructorsEv",
                    BinaryPath:       "/apex/com.android.runtime/bin/linker64",
                    UprobeOffset:     0,
                },
                {
                    Section:          "uprobe/stack",
                    EbpfFuncName:     "probe_stack",
                    AttachToFuncName: this.mconf.UprobeConf.Symbol,
                    BinaryPath:       this.mconf.UprobeConf.Library,
                    UprobeOffset:     this.mconf.UprobeConf.Offset,
                    // 这样每个hook点都使用独立的程序
                    // UID: util.RandStringBytes(8),
                },
            },

            Maps: []*manager.Map{
                {
                    Name: "soinfo_events",
                },
                {
                    Name: "stack_events",
                },
            },
        }
    }
    if this.stack_syscall_hook {
        this.bpfManager = &manager.Manager{
            Probes: []*manager.Probe{
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
                    Name: "syscall_events",
                },
            },
        }
    }

    return nil
}

func (this *MStack) setupManagerOptions() {
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
    err := this.setupManager()
    if err != nil {
        return err
    }
    this.setupManagerOptions()

    // 从assets中获取eBPF程序的二进制数据
    var bpfFileName = filepath.Join("user/bytecode", this.hookBpfFile)
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

    // uprobe hook soinfo 的过滤配置更新
    filterMap, found, err := this.bpfManager.GetMap("soinfo_filter")
    if err != nil {
        return err
    }
    if !found {
        return errors.New("cannot find soinfo_filter")
    }
    filter_key := 0
    filter := this.mconf.GetSoInfoFilter()
    filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)

    // 通过更新 BPF_MAP_TYPE_HASH 类型的 map 实现过滤设定的同步
    if this.stack_uprobe_hook {
        // uprobe hook elf 的过滤配置更新
        filterMap, found, err := this.bpfManager.GetMap("uprobe_stack_filter")
        if err != nil {
            return err
        }
        if !found {
            return errors.New("cannot find uprobe_stack_filter")
        }
        filter_key := 0
        filter := this.mconf.GetUprobeStackFilter()
        filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)
    }

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
    uprobestackEvent := &event.UprobeStackEvent{}
    this.eventFuncMaps[StackEventsMap] = uprobestackEvent

    SoInfoEventsMap, found, err := this.bpfManager.GetMap("soinfo_events")
    if err != nil {
        return err
    }
    if !found {
        return errors.New("cant found map:soinfo_events")
    }
    this.eventMaps = append(this.eventMaps, SoInfoEventsMap)
    soinfoEvent := &event.SoInfoEvent{}
    this.eventFuncMaps[SoInfoEventsMap] = soinfoEvent

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

    if e.EventType() == event.EventTypeModuleData {
        e.(*event.UprobeStackEvent).RegName = this.sconf.RegName
        e.(*event.UprobeStackEvent).ShowRegs = this.sconf.ShowRegs
        e.(*event.UprobeStackEvent).UnwindStack = this.sconf.UnwindStack
        this.logger.Println(e.(*event.UprobeStackEvent).String())
    } else {
        this.logger.Println(e.(*event.SoInfoEvent).String())
    }
}

func init() {
    mod := &MStack{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
