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
    "stackplz/user/util"
    "strings"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/btf"
    manager "github.com/ehids/ebpfmanager"
    "golang.org/x/sys/unix"
)

type MStack struct {
    Module
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]event.IEventStruct
    eventMaps         []*ebpf.Map

    hookBpfFile string
}

func (this *MStack) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
    this.Module.Init(ctx, logger, conf)
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
    if this.mconf.SysCallConf.Enable {
        this.hookBpfFile = "syscall.o"
    } else {
        this.hookBpfFile = "stack.o"
    }
    return nil
}

func (this *MStack) GetConf() config.IConfig {
    return this.mconf
}

func (this *MStack) setupManager() error {
    maps := []*manager.Map{}
    probes := []*manager.Probe{}

    events_map := &manager.Map{
        Name: "events",
    }
    maps = append(maps, events_map)

    fork_probe := &manager.Probe{
        Section:      "raw_tracepoint/sched_process_fork",
        EbpfFuncName: "tracepoint__sched__sched_process_fork",
    }
    probes = append(probes, fork_probe)

    for i, uprobe_point := range this.mconf.StackUprobeConf.Points {
        // stack hook 配置
        sym := uprobe_point.Symbol
        var stack_probe *manager.Probe
        if sym == "" {
            sym = util.RandStringBytes(8)
            stack_probe = &manager.Probe{
                Section:          fmt.Sprintf("uprobe/stack_%d", i),
                EbpfFuncName:     fmt.Sprintf("probe_stack_%d", i),
                AttachToFuncName: sym,
                BinaryPath:       uprobe_point.LibPath,
                // 这个是相对于库文件基址的偏移
                UAddress: uprobe_point.Offset,
            }
        } else {
            stack_probe = &manager.Probe{
                Section:          fmt.Sprintf("uprobe/stack_%d", i),
                EbpfFuncName:     fmt.Sprintf("probe_stack_%d", i),
                AttachToFuncName: sym,
                BinaryPath:       uprobe_point.LibPath,
                // 这个是相对于符号的偏移
                UprobeOffset: uprobe_point.Offset,
            }
        }
        if this.mconf.Debug {
            this.logger.Printf("uprobe uprobe_index:%d hook %s", i, uprobe_point.String())
        }
        probes = append(probes, stack_probe)
    }

    if this.mconf.SysCallConf.IsEnable() {
        // syscall hook 配置
        sys_enter_probe := &manager.Probe{
            Section:      "raw_tracepoint/sys_enter",
            EbpfFuncName: "raw_syscalls_sys_enter",
        }
        sys_exit_probe := &manager.Probe{
            Section:      "raw_tracepoint/sys_exit",
            EbpfFuncName: "raw_syscalls_sys_exit",
        }
        probes = append(probes, sys_enter_probe)
        probes = append(probes, sys_exit_probe)
    }

    this.bpfManager = &manager.Manager{
        Probes: probes,
        Maps:   maps,
    }
    return nil
}

func (this *MStack) setupManagerOptions() {
    // 对于没有开启 CONFIG_DEBUG_INFO_BTF 的加载额外的 btf.Spec
    if this.mconf.ExternalBTF != "" {
        byteBuf, err := assets.Asset("user/assets/" + this.mconf.ExternalBTF)
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
    } else {
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

func (this *MStack) update_map(map_name string, filter_key uint32, filter_value interface{}) {
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    err = bpf_map.Update(unsafe.Pointer(&filter_key), filter_value, ebpf.UpdateAny)
    if err != nil {
        panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
    }
    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) update_base_config() {
    // 更新 base_config 用作基础的过滤 比如排除 stackplz 自身相关的调用
    var filter_key uint32 = 0
    map_name := "base_config"
    filter_value := this.mconf.GetConfigMap()
    this.update_map(map_name, filter_key, unsafe.Pointer(&filter_value))
}

func (this *MStack) update_common_list(items []uint32, offset uint32) {
    map_name := "common_list"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    for _, v := range items {
        v += offset
        err := bpf_map.Update(unsafe.Pointer(&v), unsafe.Pointer(&v), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    if this.mconf.Debug {
        p, ok := util.START_OFFSETS[offset]
        if !ok {
            panic(fmt.Sprintf("offset%d invalid", offset))
        }
        this.logger.Printf("update %s success, count:%d offset:%s", map_name, len(items), p)
    }
}

func (this *MStack) list2string(items []uint32) string {
    var results []string
    for _, v := range items {
        results = append(results, fmt.Sprintf("%d", v))
    }
    return strings.Join(results, ",")
}

func (this *MStack) update_common_filter() {
    this.update_common_list(this.mconf.UidWhitelist, util.UID_WHITELIST_START)
    this.update_common_list(this.mconf.UidBlacklist, util.UID_BLACKLIST_START)
    this.update_common_list(this.mconf.PidWhitelist, util.PID_WHITELIST_START)
    this.update_common_list(this.mconf.PidBlacklist, util.PID_BLACKLIST_START)
    this.update_common_list(this.mconf.TidWhitelist, util.TID_WHITELIST_START)
    this.update_common_list(this.mconf.TidBlacklist, util.TID_BLACKLIST_START)
    if this.mconf.Debug {
        this.logger.Printf("uid => whitelist:[%s];blacklist:[%s]", this.list2string(this.mconf.UidWhitelist), this.list2string(this.mconf.UidBlacklist))
        this.logger.Printf("pid => whitelist:[%s];blacklist:[%s]", this.list2string(this.mconf.PidWhitelist), this.list2string(this.mconf.PidBlacklist))
        this.logger.Printf("tid => whitelist:[%s];blacklist:[%s]", this.list2string(this.mconf.TidWhitelist), this.list2string(this.mconf.TidBlacklist))
    }
    var filter_key uint32 = 0
    map_name := "common_filter"
    filter_value := this.mconf.GetCommonFilter()
    this.update_map(map_name, filter_key, unsafe.Pointer(&filter_value))
}

func (this *MStack) update_child_parent() {
    // 这个可以合并到 common_list 后面改进
    map_name := "child_parent_map"
    for _, v := range this.mconf.PidWhitelist {
        this.update_map(map_name, v, unsafe.Pointer(&v))
    }
}

func (this *MStack) update_thread_filter() {
    map_name := "thread_filter"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }

    var thread_blacklist []string = []string{
        "RenderThread",
        "FinalizerDaemon",
        "RxCachedThreadS",
        "mali-cmar-backe",
        "mali-utility-wo",
        "mali-mem-purge",
        "mali-hist-dump",
        "mali-event-hand",
        "hwuiTask0",
        "hwuiTask1",
        "NDK MediaCodec_",
    }

    for _, v := range thread_blacklist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        filter_value := THREAD_NAME_BLACKLIST
        filter_key := config.ThreadFilter{}
        copy(filter_key.ThreadName[:], v)
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    for _, v := range this.mconf.TNameBlacklist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        filter_value := THREAD_NAME_BLACKLIST
        filter_key := config.ThreadFilter{}
        copy(filter_key.ThreadName[:], v)
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    for _, v := range this.mconf.TNameWhitelist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        filter_value := THREAD_NAME_WHITELIST
        filter_key := config.ThreadFilter{}
        copy(filter_key.ThreadName[:], v)
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }

    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) update_arg_filter() {
    map_name := "arg_filter"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    // w/white b/black
    // ./stackplz -n com.starbucks.cn -s openat:f0 -f w:/system/framework/oat -o tmp.log
    // ./stackplz -n com.starbucks.cn -w strstr[str:x1:f0] -f w:/data/local/tmp -o tmp.log
    // ./stackplz -n com.starbucks.cn -w strstr[str:f0,str:f1] -f w:/data/local/tmp -r w:/data/local/tmp -o tmp.log
    // r/replace 文本替换逻辑会比较复杂 应该考虑分离
    for _, filter := range this.mconf.ArgFilterRule {
        filter_key := filter.Filter_index
        filter_value := filter
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) update_syscall_point_args() {
    map_name := "syscall_point_args_map"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    if this.mconf.SysCallConf.TraceMode == config.TRACE_ALL {
        points := config.GetAllWatchPoints()
        for nr_name, point := range points {
            nr_point, ok := (point).(*config.SysCallArgs)
            if !ok {
                panic(fmt.Sprintf("cast [%s] point to SysCallArgs failed", nr_name))
            }
            err := bpf_map.Update(unsafe.Pointer(&nr_point.NR), unsafe.Pointer(nr_point.GetConfig()), ebpf.UpdateAny)
            if err != nil {
                panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
            }
        }
    } else {
        for _, point_args := range this.mconf.SysCallConf.SyscallPointArgs {
            err := bpf_map.Update(unsafe.Pointer(&point_args.NR), unsafe.Pointer(point_args), ebpf.UpdateAny)
            if err != nil {
                panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
            }
        }
    }

    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }

}

func (this *MStack) update_syscall_config() {
    if !this.mconf.SysCallConf.IsEnable() {
        return
    }
    this.update_syscall_point_args()
    this.update_common_list(this.mconf.SysCallConf.SysWhitelist, util.SYS_WHITELIST_START)
    this.update_common_list(this.mconf.SysCallConf.SysBlacklist, util.SYS_BLACKLIST_START)
    if this.mconf.Debug {
        this.logger.Printf("SysCallConf:%s", this.mconf.SysCallConf.Info())
    }
}

func (this *MStack) update_stack_config() {
    if !this.mconf.StackUprobeConf.IsEnable() {
        return
    }
    map_name := "uprobe_point_args_map"
    bpf_map, err := this.FindMap("uprobe_point_args_map")
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    for _, uprobe_point := range this.mconf.StackUprobeConf.Points {
        var filter_key uint32 = uprobe_point.Index
        filter_value := uprobe_point.GetConfig()
        err := bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, filter_key:%d, err:%v", map_name, filter_key, err))
        }
    }
    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) updateFilter() (err error) {
    this.update_base_config()
    this.update_common_filter()
    this.update_child_parent()
    this.update_thread_filter()
    this.update_arg_filter()
    this.update_stack_config()
    this.update_syscall_config()
    return nil
}

func (this *MStack) initDecodeFun() error {

    EventsMap, err := this.FindMap("events")
    if err != nil {
        return err
    }
    this.eventMaps = append(this.eventMaps, EventsMap)
    commonEvent := &event.CommonEvent{}
    commonEvent.SetConf(this.mconf)
    this.eventFuncMaps[EventsMap] = commonEvent

    this.eventMaps = append(this.eventMaps, EventsMap)
    // 根据设置添加 map 不然即使不使用的map也会创建缓冲区
    if this.mconf.StackUprobeConf.IsEnable() {
        uprobestackEvent := &event.UprobeEvent{}
        this.eventFuncMaps[EventsMap] = uprobestackEvent
    }

    if this.mconf.SysCallConf.IsEnable() {
        syscallEvent := &event.SyscallEvent{}
        this.eventFuncMaps[EventsMap] = syscallEvent
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

func init() {
    mod := &MStack{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
