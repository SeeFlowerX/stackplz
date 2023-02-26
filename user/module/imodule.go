package module

import (
    "context"
    "errors"
    "fmt"
    "log"
    "os"
    "reflect"
    "stackplz/user/config"
    "stackplz/user/event"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/perf"
    "github.com/cilium/ebpf/ringbuf"
)

type IModule interface {
    // Init 初始化
    Init(context.Context, *log.Logger, config.IConfig) error

    // Name 获取当前module的名字
    Name() string

    Clone() IModule

    GetConf() config.IConfig

    // Run 事件监听感知
    Run() error

    // Start 启动模块
    Start() error

    // Stop 停止模块
    Stop() error

    // Close 关闭退出
    Close() error

    SetChild(module IModule)

    Decode(*ebpf.Map, []byte) (event.IEventStruct, error)

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
    name         string
    unwind_stack bool

    // module的类型，uprobe,kprobe等
    mType string

    sconf *config.SConfig

    // processor *event_processor.EventProcessor
}

// Init 对象初始化
func (this *Module) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) {
    this.ctx = ctx
    this.logger = logger
    this.sconf = conf.GetSConfig()
    // if ok {
    //     this.sconf = sconf
    // } else {
    //     panic("cannot convert conf to SConfig")
    // }
    // this.processor = event_processor.NewEventProcessor(logger)

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

    // 在一端不断接收readEvents所传递的数据 或许这样可以避免阻塞
    // go func() {
    //     this.processor.Serve()
    // }()

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
            // 暂时没有用上这个类型的 暂时保留
            this.ringbufEventReader(errChan, ebpfMap)
        case ebpfMap.Type() == ebpf.PerfEventArray:
            this.perfEventReader(errChan, ebpfMap)
        default:
            return fmt.Errorf("%s\tNot support mapType:%s , mapinfo:%s", this.child.Name(), ebpfMap.Type().String(), ebpfMap.String())
        }
    }

    return nil
}

func (this *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
    // 这里对原ebpf包代码做了修改 以此控制是否让内核发生栈空间数据和寄存器数据
    // 用于进行堆栈回溯 以后可以细分栈数据与寄存器数据
    // 每个 模块都是 Clone 得到的 map 虽然名字相同 但是 fd不同 所以可以正常区分

    map_value := reflect.ValueOf(em)
    map_name := map_value.Elem().FieldByName("name")
    IsSoInfoMap := map_name.String() == "soinfo_events"

    var rd *perf.Reader
    var err error
    // soinfo 不管如何都不需要或者堆栈和寄存器信息
    if IsSoInfoMap {
        rd, err = perf.NewReader(em, os.Getpagesize()*512, false, false)
    } else if this.sconf.RegName != "" {
        rd, err = perf.NewReader(em, os.Getpagesize()*512, this.sconf.UnwindStack, true)
    } else {
        rd, err = perf.NewReader(em, os.Getpagesize()*512, this.sconf.UnwindStack, this.sconf.ShowRegs)
    }
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

            var record perf.Record
            // 根据预设的flag决定以何种方式读取事件数据
            if IsSoInfoMap {
                record, err = rd.Read()
            } else if this.sconf.UnwindStack {
                record, err = rd.ReadWithUnwindStack()
            } else if this.sconf.ShowRegs {
                record, err = rd.ReadWithRegs()
            } else if this.sconf.RegName != "" {
                record, err = rd.ReadWithRegs()
            } else {
                record, err = rd.Read()
            }

            if err != nil {
                if errors.Is(err, perf.ErrClosed) {
                    return
                }
                errChan <- fmt.Errorf("%s\treading from perf event reader: %s", this.child.Name(), err)
                return
            }

            if record.LostSamples != 0 {
                this.logger.Printf("%s\tperf event ring buffer full, dropped %d samples, %s", this.child.Name(), record.LostSamples, map_name)
                continue
            }

            var e event.IEventStruct
            // 读取到事件数据之后 立刻开始解析获取结果
            e, err = this.child.Decode(em, record.RawSample)
            if err != nil {
                this.logger.Printf("%s\tthis.child.decode error:%v", this.child.Name(), err)
                continue
            }

            // 事件数据解析完成之后上报数据，比如写入日志获取输出到特定格式文件中
            this.Dispatcher(e)
        }
    }()
}

func (this *Module) ringbufEventReader(errChan chan error, em *ebpf.Map) {
    rd, err := ringbuf.NewReader(em)
    if err != nil {
        errChan <- fmt.Errorf("%s\tcreating %s reader dns: %s", this.child.Name(), em.String(), err)
        return
    }
    this.reader = append(this.reader, rd)
    go func() {
        for {
            //判断ctx是不是结束
            select {
            case _ = <-this.ctx.Done():
                this.logger.Printf("%s\tringbufEventReader received close signal from context.Done().", this.child.Name())
                return
            default:
            }

            record, err := rd.Read()
            if err != nil {
                if errors.Is(err, ringbuf.ErrClosed) {
                    this.logger.Printf("%s\tReceived signal, exiting..", this.child.Name())
                    return
                }
                errChan <- fmt.Errorf("%s\treading from ringbuf reader: %s", this.child.Name(), err)
                return
            }

            var e event.IEventStruct
            e, err = this.child.Decode(em, record.RawSample)
            if err != nil {
                this.logger.Printf("%s\tthis.child.decode error:%v", this.child.Name(), err)
                continue
            }

            // 上报数据
            this.Dispatcher(e)
        }
    }()
}

func (this *Module) Decode(em *ebpf.Map, b []byte) (event event.IEventStruct, err error) {
    // 首先根据map得到最开始设置好的用于解析的结构体引用（这样描述可能不对）
    es, found := this.child.DecodeFun(em)
    if !found {
        err = fmt.Errorf("%s\tcan't found decode function :%s, address:%p", this.child.Name(), em.String(), em)
        return
    }
    // 通过结构体引用生成一个真正用于解析事件数据的实例
    // 注意这里会设置好 event_type 后续上报数据需要根据这个类型判断使用何种上报方式
    te := es.Clone()
    te.SetConf(this.child.GetConf())
    // 正式解析，传入是否进行堆栈回溯的标志
    if this.sconf.RegName != "" {
        err = te.Decode(b, this.sconf.UnwindStack, true)
    } else {
        err = te.Decode(b, this.sconf.UnwindStack, this.sconf.ShowRegs)
    }
    if err != nil {
        return nil, err
    }
    // 解析完成 可以用于事件上报处理
    return te, nil
}

// 写入数据，或者上传到远程数据库，写入到其他chan 等。
func (this *Module) Dispatcher(e event.IEventStruct) {
    switch e.EventType() {
    case event.EventTypeModuleData:
        // Save to cache
        this.child.Dispatcher(e)
    case event.EventTypeSoInfoData:
        this.logger.Println(e.(*event.SoInfoEvent).String())
    case event.EventTypeSysCallData:
        this.logger.Println(e.(*event.SyscallEvent).String())
    }
}

func (this *Module) Close() error {
    if this.sconf.Debug {
        this.logger.Printf("%s\tClose", this.child.Name())
    }
    for _, iClose := range this.reader {
        if err := iClose.Close(); err != nil {
            return err
        }
    }
    // err := this.processor.Close()
    // return err
    return nil
}
