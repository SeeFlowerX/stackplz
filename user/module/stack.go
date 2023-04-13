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
    "github.com/cilium/ebpf/btf"
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

    hookBpfFile string
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

func (this *MStack) GetConf() config.IConfig {
    return this.mconf
}

func (this *MStack) setupManager() error {
    maps := []*manager.Map{}
    probes := []*manager.Probe{}

    // soinfo hook 配置
    vmainfo_kprobe := &manager.Probe{
        Section:          "kprobe/vma_set_page_prot",
        EbpfFuncName:     "kprobe_vma_set_page_prot",
        AttachToFuncName: "vma_set_page_prot",
    }
    vmainfo_kretprobe := &manager.Probe{
        Section:          "kretprobe/vma_set_page_prot",
        EbpfFuncName:     "kretprobe_vma_set_page_prot",
        AttachToFuncName: "vma_set_page_prot",
    }
    // soinfo hook 配置
    // soinfo_probe := &manager.Probe{
    //     Section:          "uprobe/soinfo",
    //     EbpfFuncName:     "probe_soinfo",
    //     AttachToFuncName: "__dl__ZN6soinfo17call_constructorsEv",
    //     BinaryPath:       "/apex/com.android.runtime/bin/linker64",
    //     UprobeOffset:     0,
    // }
    // soinfo_events_map := &manager.Map{
    //     Name: "soinfo_events",
    // }
    // 不管是 stack 还是 syscall 都需要用到 soinfo
    probes = append(probes, vmainfo_kprobe)
    probes = append(probes, vmainfo_kretprobe)
    // probes = append(probes, soinfo_probe)
    // maps = append(maps, soinfo_events_map)

    // stack hook 配置
    stack_probe := &manager.Probe{
        Section:          "uprobe/stack",
        EbpfFuncName:     "probe_stack",
        AttachToFuncName: this.mconf.StackUprobeConf.Symbol,
        BinaryPath:       this.mconf.StackUprobeConf.Library,
        UprobeOffset:     this.mconf.StackUprobeConf.Offset,
        // 这样每个hook点都使用独立的程序
        // UID: util.RandStringBytes(8),
    }
    stack_events_map := &manager.Map{
        Name: "stack_events",
    }

    // syscall hook 配置
    sys_enter_probe := &manager.Probe{
        Section:      "raw_tracepoint/sys_enter",
        EbpfFuncName: "raw_syscalls_sys_enter",
    }
    sys_exit_probe := &manager.Probe{
        Section:      "raw_tracepoint/sys_exit",
        EbpfFuncName: "raw_syscalls_sys_exit",
    }
    syscall_events_map := &manager.Map{
        Name: "syscall_events",
    }

    if this.mconf.StackUprobeConf.IsEnable() {
        if this.mconf.Debug {
            this.logger.Printf("Symbol:%s Library:%s Offset:0x%x", this.mconf.StackUprobeConf.Symbol, this.mconf.StackUprobeConf.Library, this.mconf.StackUprobeConf.Offset)
        }
        probes = append(probes, stack_probe)
        maps = append(maps, stack_events_map)
    }

    if this.mconf.SysCallConf.IsEnable() {
        if this.mconf.Debug {
            this.logger.Printf("Syscall:%s", this.mconf.SysCallConf.Info())
        }
        probes = append(probes, sys_enter_probe)
        probes = append(probes, sys_exit_probe)
        maps = append(maps, syscall_events_map)
    }

    this.bpfManager = &manager.Manager{
        Probes: probes,
        Maps:   maps,
    }
    return nil
}

func (this *MStack) setupManagerOptions() {
    // 对于没有开启 CONFIG_DEBUG_INFO_BTF 的加载额外的 btf.Spec
    byteBuf, err := assets.Asset("user/assets/a12-5.10-arm64_min.btf")
    if err != nil {
        this.logger.Fatalf("[setupManagerOptions] failed, err:%v", err)
        return
    }
    spec, err := btf.LoadSpecFromReader((bytes.NewReader(byteBuf)))

    this.bpfManagerOptions = manager.Options{
        DefaultKProbeMaxActive: 512,
        VerifierOptions: ebpf.CollectionOptions{
            Programs: ebpf.ProgramOptions{
                LogSize:     2097152,
                KernelTypes: spec,
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

    // 先判断有是只hook其中一个 还是两个都要
    if !this.mconf.StackUprobeConf.IsEnable() && !this.mconf.SysCallConf.IsEnable() {
        return errors.New("hook nothing")
    }

    // 初始化uprobe相关设置
    err := this.setupManager()
    if err != nil {
        return err
    }
    this.setupManagerOptions()

    // 从assets中获取eBPF程序的二进制数据
    var bpfFileName = filepath.Join("user/assets", this.hookBpfFile)
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

    // 通过更新 BPF_MAP_TYPE_HASH 类型的 map 实现过滤设定的同步
    err = this.updateFilter()
    if err != nil {
        return err
    }

    // 加载map信息，设置eventFuncMaps，给不同的事件指定处理事件数据的函数
    err = this.initDecodeFun()
    if err != nil {
        return err
    }

    return nil
}

func (this *MStack) updateFilter() error {
    // uprobe hook soinfo 的过滤配置更新
    filterMap, err := this.FindMap("soinfo_filter")
    if err != nil {
        return err
    }
    filter_key := 0
    filter := this.mconf.GetSoInfoFilter()
    filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)

    vfilterMap, err := this.FindMap("vmainfo_filter")
    if err != nil {
        return err
    }
    vfilter_key := 0
    vfilter := this.mconf.GetVmaInfoFilter()
    err = vfilterMap.Update(unsafe.Pointer(&vfilter_key), unsafe.Pointer(&vfilter), ebpf.UpdateAny)
    if err != nil {
        fmt.Println("eeeeeeeeeeeeeeeeeee")
        return err
    }
    fmt.Println("oooooooooooo")
    // uprobe hook stack 的过滤配置更新
    if this.mconf.StackUprobeConf.IsEnable() {
        filterMap, err = this.FindMap("uprobe_stack_filter")
        if err != nil {
            return err
        }
        filter_key := 0
        filter := this.mconf.GetUprobeStackFilter()
        filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)
        this.logger.Println("hook for stack, update uprobe_stack_filter end")
    }

    // raw syscall hook 的过滤配置更新
    if this.mconf.SysCallConf.IsEnable() {
        filterMap, err = this.FindMap("arg_mask_map")
        if err != nil {
            return err
        }
        this.mconf.SysCallConf.UpdateArgMaskMap(filterMap)
        filterMap, err = this.FindMap("arg_ret_mask_map")
        if err != nil {
            return err
        }
        this.mconf.SysCallConf.UpdateArgRetMaskMap(filterMap)
        filterMap, err = this.FindMap("syscall_filter")
        if err != nil {
            return err
        }
        filter_key := 0
        filter := this.mconf.GetSyscallFilter()
        filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)
        this.logger.Println("hook for syscall, update syscall_filter end")
    }
    return nil
}
func (this *MStack) initDecodeFun() error {
    // 根据设置添加 map 不然即使不使用的map也会创建缓冲区
    if this.mconf.StackUprobeConf.IsEnable() {
        StackEventsMap, err := this.FindMap("stack_events")
        if err != nil {
            return err
        }
        this.eventMaps = append(this.eventMaps, StackEventsMap)
        uprobestackEvent := &event.UprobeStackEvent{}
        this.eventFuncMaps[StackEventsMap] = uprobestackEvent
    }

    SoInfoEventsMap, err := this.FindMap("soinfo_events")
    if err != nil {
        return err
    }
    this.eventMaps = append(this.eventMaps, SoInfoEventsMap)
    soinfoEvent := &event.SoInfoEvent{}
    this.eventFuncMaps[SoInfoEventsMap] = soinfoEvent

    if this.mconf.SysCallConf.IsEnable() {
        SysCallEventsMap, err := this.FindMap("syscall_events")
        if err != nil {
            return err
        }
        this.eventMaps = append(this.eventMaps, SysCallEventsMap)
        syscallEvent := &event.SyscallEvent{}
        this.eventFuncMaps[SysCallEventsMap] = syscallEvent
    }

    return nil
}

func (this *MStack) FindMap(map_name string) (*ebpf.Map, error) {
    em, found, err := this.bpfManager.GetMap(map_name)
    if err != nil {
        return em, err
    }
    if !found {
        return em, errors.New(fmt.Sprintf("cannot find map:%s", map_name))
    }
    return em, err
}

func (this *MStack) Events() []*ebpf.Map {
    return this.eventMaps
}

func (this *MStack) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
    fun, found := this.eventFuncMaps[em]
    return fun, found
}

// func (this *MStack) Dispatcher(e event.IEventStruct) {
//     // 事件类型指定为 EventTypeModuleData 直接使用当前方法处理
//     // 如果需要多处联动收集信息 比如做统计之类的 那么使用 EventTypeEventProcessor 类型 并设计处理模式更合理

//     e.(*event.UprobeStackEvent).RegName = this.sconf.RegName
//     e.(*event.UprobeStackEvent).ShowRegs = this.sconf.ShowRegs
//     e.(*event.UprobeStackEvent).UnwindStack = this.sconf.UnwindStack
//     this.logger.Println(e.(*event.UprobeStackEvent).String())
// }

func init() {
    mod := &MStack{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
