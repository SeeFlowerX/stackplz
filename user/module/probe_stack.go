package module

import (
    "bytes"
    "context"
    "edemo/assets"
    "edemo/user/config"
    "edemo/user/event"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "math"
    "math/rand"
    "os"
    "path/filepath"

    "github.com/cilium/ebpf"
    manager "github.com/ehids/ebpfmanager"
    "golang.org/x/sys/unix"
)

type MStackProbe struct {
    Module
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]event.IEventStruct
    eventMaps         []*ebpf.Map

    hookBpfMap  map[string]string
    hookBpfFile string
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(b)
}

func (this *MStackProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
    this.Module.Init(ctx, logger, conf)
    this.conf = conf
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
    this.hookBpfMap = map[string]string{
        "default": "stack.o",
    }
    return nil
}

func (this *MStackProbe) getBpfFile(bpf_key string) error {
    if bpf_key != "" {
        bpfFile, found := this.hookBpfMap[bpf_key]
        if found {
            this.hookBpfFile = bpfFile
            return nil
        } else {
            this.hookBpfFile = this.hookBpfMap["default"]
        }
    }

    return nil
}

func (this *MStackProbe) setupManagersUprobe() error {
    libPath := this.conf.(*config.StackConfig).Libpath
    libSymbol := this.conf.(*config.StackConfig).Symbol
    libOffset := this.conf.(*config.StackConfig).Offset

    _, err := os.Stat(libPath)
    if err != nil {
        return err
    }

    err = this.getBpfFile(libPath)
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
    this.logger.Println(e.(*event.HookDataEvent).String())
}

func init() {
    mod := &MStackProbe{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
