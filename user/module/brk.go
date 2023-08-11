package module

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"stackplz/user/config"
	"stackplz/user/event"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type PerfBRK struct {
	Module
	mconf         *config.ModuleConfig
	eventFuncMaps map[*ebpf.Map]event.IEventStruct
	eventMaps     []*ebpf.Map
}

func (this *PerfBRK) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	p, ok := (conf).(*config.ModuleConfig)
	if ok {
		this.mconf = p
	}
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (this *PerfBRK) GetConf() config.IConfig {
	return this.mconf
}

func (this *PerfBRK) Start() error {
	return this.start()
}

func (this *PerfBRK) Clone() IModule {
	mod := new(PerfBRK)
	mod.name = this.name
	mod.mType = this.mType
	return mod
}

func (this *PerfBRK) start() (err error) {
	err = this.initDecodeFun()
	if err != nil {
		return err
	}
	return nil
}

func (this *PerfBRK) initDecodeFun() (err error) {
	err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	})
	if err != nil {
		return errors.New(fmt.Sprintf("error:%v , couldn't adjust RLIMIT_MEMLOCK", err))
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "brk_map",
		Type: ebpf.PerfEventArray,
	})
	if err != nil {
		return err
	}

	this.eventMaps = append(this.eventMaps, events)
	commonEvent := &event.CommonEvent{}
	commonEvent.SetConf(this.mconf)
	this.eventFuncMaps[events] = commonEvent

	return nil
}

func (this *PerfBRK) Events() []*ebpf.Map {
	return this.eventMaps
}

func (this *PerfBRK) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func init() {
	mod := &PerfBRK{}
	mod.name = MODULE_NAME_BRK
	mod.mType = PROBE_TYPE_BREAKPOINT
	Register(mod)
}
