package module

import (
    "bytes"
    "context"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "math"
    "math/rand"
    "os"
    "path/filepath"
    "stackplz/assets"
    "stackplz/user/config"
    "stackplz/user/event"
    "strconv"
    "strings"

    "github.com/cilium/ebpf"
    manager "github.com/ehids/ebpfmanager"
    "golang.org/x/exp/slices"
    "golang.org/x/sys/unix"
)

type MStackProbe struct {
    Module
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]event.IEventStruct
    eventMaps         []*ebpf.Map

    hookBpfFile string
}

type BaseHookConfig struct {
    Unwindstack bool     `json:"unwindstack"`
    Regs        bool     `json:"regs"`
    Symbols     []string `json:"symbols"`
    Offsets     []string `json:"offsets"`
}

type LibHookConfig struct {
    Path    string           `json:"path"`
    Configs []BaseHookConfig `json:"configs"`
}

type HookConfig struct {
    Uid  uint64          `json:"uid"`
    Libs []LibHookConfig `json:"libs"`
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(b)
}

func hex2int(hexStr string) uint64 {
    cleaned := strings.Replace(hexStr, "0x", "", -1)
    result, _ := strconv.ParseUint(cleaned, 16, 64)
    return uint64(result)
}

func (this *MStackProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
    this.Module.Init(ctx, logger, conf)
    this.conf = conf
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
    this.hookBpfFile = "stack.o"
    return nil
}

func (this *MStackProbe) setupManagerWithConfig() error {
    // 取文件
    config_path := this.conf.(*config.StackConfig).ConfigFile
    // 以 / 开头的当作全路径读取
    if !strings.HasPrefix(config_path, "/") {
        // 否则先检查是否直接存在
        if _, err := os.Stat(config_path); err != nil {
            // 不存在则尝试拼接可执行程序所在文件夹路径
            ex, err := os.Executable()
            if err != nil {
                panic(err)
            }
            config_path = filepath.Dir(ex) + "/" + config_path
        }
    }

    content, err := ioutil.ReadFile(config_path)
    if err != nil {
        return fmt.Errorf("Error when opening file:%v", err)
    }
    // 按特定格式解析
    var hookConfig HookConfig
    json.Unmarshal(content, &hookConfig)
    // 如果命令行指定了uid 以命令行的为准
    if this.conf.GetUid() != 0 {
        hookConfig.Uid = this.conf.GetUid()
    }

    var probes []*manager.Probe
    for _, libHookConfig := range hookConfig.Libs {
        // 目标库
        libPath := libHookConfig.Path
        // 用于对每个库的配置去重
        var symbols []string
        var offsets []string
        for _, baseHookConfig := range libHookConfig.Configs {
            // 按符号
            for _, symbol := range baseHookConfig.Symbols {
                if strings.Trim(symbol, " ") == "" {
                    continue
                }
                // 符号去重
                if slices.Contains(symbols, symbol) {
                    this.logger.Printf("duplicated symbol:%s", symbol)
                    continue
                } else {
                    symbols = append(symbols, symbol)
                }
                probe := manager.Probe{
                    Section:          "uprobe/stack",
                    EbpfFuncName:     "probe_stack",
                    AttachToFuncName: symbol,
                    BinaryPath:       libPath,
                    UprobeOffset:     0,
                    // 这样每个hook点都使用独立的程序
                    UID: RandStringBytes(8),
                }
                probes = append(probes, &probe)
            }
            // 按偏移
            for _, offset := range baseHookConfig.Offsets {
                if strings.Trim(offset, " ") == "" {
                    continue
                }
                // 偏移必须以 0x 开头
                if !strings.HasPrefix(offset, "0x") {
                    this.logger.Printf("must start with 0x, offset:%s", offset)
                    continue
                }
                // 偏移去重
                if slices.Contains(offsets, offset) {
                    this.logger.Printf("duplicated offset:%s", offset)
                    continue
                } else {
                    offsets = append(offsets, offset)
                }
                probe := manager.Probe{
                    Section:          "uprobe/stack",
                    EbpfFuncName:     "probe_stack",
                    AttachToFuncName: RandStringBytes(8),
                    BinaryPath:       libPath,
                    UprobeOffset:     hex2int(offset),
                    UID:              RandStringBytes(8),
                }
                probes = append(probes, &probe)
            }
        }
    }
    // 初始化 bpfManager
    this.bpfManager = &manager.Manager{
        Probes: probes,
        Maps: []*manager.Map{
            {
                Name: "stack_events",
            },
        },
    }

    return nil
}

func (this *MStackProbe) setupManager() error {

    libPath := this.conf.(*config.StackConfig).Libpath
    libSymbol := this.conf.(*config.StackConfig).Symbol
    libOffset := this.conf.(*config.StackConfig).Offset

    _, err := os.Stat(libPath)
    if err != nil {
        return err
    }

    if libSymbol == "" && libOffset == 0 {
        return fmt.Errorf("need symbol or offset\n")
    }

    if libSymbol != "" && libOffset > 0 {
        return fmt.Errorf("just symbol or offset, not all of them\n")
    }

    if libSymbol != "" {
        this.logger.Printf("%s\tlibPath:%s libSymbol:%s\n", this.Name(), libPath, libSymbol)
    }

    if libOffset > 0 {
        this.logger.Printf("%s\tlibPath:%s libOffset:0x%x\n", this.Name(), libPath, libOffset)
        // 虽然前面不允许用户同时设置offset和symbol 但是ebpf库必须要有一个symbol 于是这里随机下就好了
        libSymbol = RandStringBytes(8)
    }

    this.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "uprobe/stack",
                EbpfFuncName:     "probe_stack",
                AttachToFuncName: libSymbol,
                BinaryPath:       libPath,
                UprobeOffset:     libOffset,
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
    if this.conf.(*config.StackConfig).ConfigFile == "" {
        err := this.setupManager()
        if err != nil {
            return err
        }
    } else {
        err := this.setupManagerWithConfig()
        if err != nil {
            return err
        }
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

func IntToBytes(n int) []byte {
    x := int32(n)
    bytesBuffer := bytes.NewBuffer([]byte{})
    binary.Write(bytesBuffer, binary.LittleEndian, x)
    return bytesBuffer.Bytes()
}

func (this *MStackProbe) start() error {
    // 初始化Uprobe相关设置
    err := this.setupManagersUprobe()
    if err != nil {
        return err
    }

    // 从assets中获取eBPF程序的二进制数据
    var bpfFileName = filepath.Join("user/bytecode", this.hookBpfFile)
    this.logger.Printf("%s\tBPF bytecode filename:%s\n", this.Name(), bpfFileName)
    byteBuf, err := assets.Asset(bpfFileName)

    // 通过直接替换二进制数据实现uid过滤
    target_uid_buf := []byte{0xAA, 0xCC, 0xBB, 0xAA}
    uid_buf := IntToBytes(int(this.conf.GetUid()))
    byteBuf = bytes.Replace(byteBuf, target_uid_buf, uid_buf, 3)

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

    e.(*event.HookDataEvent).ShowRegs = this.conf.GetShowRegs()
    e.(*event.HookDataEvent).UnwindStack = this.conf.GetUnwindStack()
    this.logger.Println(e.(*event.HookDataEvent).String())
}

func init() {
    mod := &MStackProbe{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
