package module

import (
    "context"
    "errors"
    "fmt"
    "log"
    "os"
    "stackplz/user/config"
    "stackplz/user/event"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/perf"
)

type IModule interface {
    Init(context.Context, *log.Logger, config.IConfig) error

    Name() string

    Clone() IModule

    GetConf() config.IConfig

    Run() error

    Start() error

    Stop() error

    Close() error

    SetChild(module IModule)

    PrePare(*ebpf.Map, perf.Record) (event.IEventStruct, error)

    Events() []*ebpf.Map

    DecodeFun(p *ebpf.Map) (event.IEventStruct, bool)

    Dispatcher(event.IEventStruct)
}

type Module struct {
    opts   *ebpf.CollectionOptions
    reader []IClose
    ctx    context.Context
    logger *log.Logger
    child  IModule
    // probe的名字
    name string
    // module的类型，uprobe,kprobe等
    mType string
    sconf *config.SConfig
}

func (this *Module) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) {
    this.ctx = ctx
    this.logger = logger
    this.sconf = conf.GetSConfig()

}

func (this *Module) Clone() IModule {
    panic("Module.Clone() not implemented yet")
}

func (this *Module) GetConf() config.IConfig {
    panic("Module.GetConf() not implemented yet")
}

func (this *Module) SetChild(module IModule) {
    this.child = module
}

func (this *Module) Start() error {
    panic("Module.Start() not implemented yet")
}

func (this *Module) Events() []*ebpf.Map {
    panic("Module.Events() not implemented yet")
}

func (this *Module) DecodeFun(p *ebpf.Map) (event.IEventStruct, bool) {
    panic("Module.DecodeFun() not implemented yet")
}

func (this *Module) Name() string {
    return this.name
}

func (this *Module) Run() error {
    // this.logger.Printf("%s\tModule.Run()", this.Name())
    //  加载全部eBPF程序
    err := this.child.Start()
    if err != nil {
        return err
    }

    // 不断检查是否有外部导致的终止，有则停止加载的模块并退出
    go func() {
        this.run()
    }()

    // 不断读取内核传递过来的事件
    err = this.readEvents()
    if err != nil {
        return err
    }

    return nil
}
func (this *Module) Stop() error {
    return nil
}

// Stop shuts down Module
func (this *Module) run() {
    for {
        select {
        case _ = <-this.ctx.Done():
            err := this.child.Stop()
            if err != nil {
                this.logger.Fatalf("%s\t stop Module error:%v.", this.child.Name(), err)
            }
            return
        }
    }
}

func (this *Module) readEvents() error {
    var errChan = make(chan error, 8)
    // 随时记录读取事件过程中的异常情况
    go func() {
        for {
            select {
            case err := <-errChan:
                this.logger.Printf("%s\treadEvents error:%v", this.child.Name(), err)
            }
        }
    }()
    // 读取之前从eBPF程序中解析预设的map的事件数据
    for _, ebpfMap := range this.child.Events() {
        switch {
        case ebpfMap.Type() == ebpf.RingBuf:
            panic("not support RingBuf")
        case ebpfMap.Type() == ebpf.PerfEventArray:
            this.perfEventReader(errChan, ebpfMap)
        default:
            return fmt.Errorf("%s\tNot support mapType:%s , mapinfo:%s", this.child.Name(), ebpfMap.Type().String(), ebpfMap.String())
        }
    }

    return nil
}

func (this *Module) getExtraOptions(em *ebpf.Map) perf.ExtraPerfOptions {
    // 这里可以考虑在一开始的时候就完成初始化
    var RegMask uint64
    // if this.sconf.Is32Bit {
    //     RegMask = (1 << PERF_REG_ARM_MAX) - 1
    // } else {
    // RegMask = (1 << PERF_REG_ARM64_MAX) - 1
    RegMask = (1 << 33) - 1
    // }
    var ShowRegs bool
    if this.sconf.RegName != "" {
        ShowRegs = true
    } else {
        ShowRegs = this.sconf.ShowRegs
    }

    return perf.ExtraPerfOptions{
        UnwindStack:       this.sconf.UnwindStack,
        ShowRegs:          ShowRegs,
        PerfMmap:          false,
        BrkAddr:           0,
        BrkType:           0,
        Sample_regs_user:  RegMask,
        Sample_stack_user: 8192,
    }
}

func (this *Module) getPerCPUBuffer() int {
    return os.Getpagesize() * (int(8) * 1024 / 4)
}

func (this *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
    // 这里对原ebpf包代码做了修改 以此控制是否让内核发生栈空间数据和寄存器数据
    // 用于进行堆栈回溯 以后可以细分栈数据与寄存器数据
    // 每个 模块都是 Clone 得到的 map 虽然名字相同 但是 fd不同 所以可以正常区分
    var rd *perf.Reader
    var err error

    eopt := this.getExtraOptions(em)

    rd, err = perf.NewReaderWithOptions(em, this.getPerCPUBuffer(), perf.ReaderOptions{}, eopt)

    if err != nil {
        errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
        return
    }
    // 可能存在多种类型的reader 添加到reader列表 异常时便于一起安全关闭
    this.reader = append(this.reader, rd)
    go func() {
        for {
            // 先判断ctx正不正常
            select {
            case _ = <-this.ctx.Done():
                this.logger.Printf("%s\tperfEventReader received close signal from context.Done().", this.child.Name())
                return
            default:
            }

            record, err := rd.ReadWithExtraOptions(&eopt)
            if err != nil {
                if errors.Is(err, perf.ErrClosed) {
                    return
                }
                errChan <- fmt.Errorf("%s\treading from perf event reader: %s", this.child.Name(), err)
                return
            }

            if record.LostSamples != 0 {
                this.logger.Printf("%s\tperf event ring buffer full, dropped %d samples, %s", this.child.Name(), record.LostSamples, this.child.GetConf())
                continue
            }

            // 读取到事件数据之后 立刻开始解析获取结果
            var e event.IEventStruct
            e, err = this.child.PrePare(em, record)
            if err != nil {
                this.logger.Printf("%s\tthis.child.decode error:%v", this.child.Name(), err)
                continue
            }
            // 事件数据解析完成之后上报数据，比如写入日志获取输出到特定格式文件中
            this.Dispatcher(e)
        }
    }()
}

func (this *Module) PrePare(em *ebpf.Map, rec perf.Record) (event event.IEventStruct, err error) {
    // 首先根据map得到最开始设置好的用于解析的结构体引用（这样描述可能不对）
    es, found := this.child.DecodeFun(em)
    if !found {
        err = fmt.Errorf("%s\tcan't found decode function :%s, address:%p", this.child.Name(), em.String(), em)
        return nil, err
    }
    te := es.Clone()
    te.SetLogger(this.logger)
    te.SetConf(this.child.GetConf())
    te.SetRecord(rec)
    return te, nil
}

// 写入数据，或者上传到远程数据库，写入到其他chan 等。
func (this *Module) Dispatcher(e event.IEventStruct) {
    this.child.Dispatcher(e)
}

func (this *Module) Close() error {
    if this.sconf.Debug {
        this.logger.Printf("%s\tClose, %s", this.child.Name(), this.child.GetConf())
    }
    for _, iClose := range this.reader {
        if err := iClose.Close(); err != nil {
            return err
        }
    }
    return nil
}
