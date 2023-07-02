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

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type PerfMMAP struct {
	Module
	mconf             *config.ModuleConfig
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	hookBpfFile string
}

func (this *PerfMMAP) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	this.Module.Init(ctx, logger, conf)
	p, ok := (conf).(*config.ModuleConfig)
	if ok {
		this.mconf = p
	}
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	this.hookBpfFile = "perf_mmap.o"
	return nil
}

func (this *PerfMMAP) GetConf() config.IConfig {
	return this.mconf
}

func (this *PerfMMAP) setupManager() error {
	// 只采集 mmap comm mmap2 的数据 实际上不涉及 ebpf map/probe
	maps := []*manager.Map{}
	probes := []*manager.Probe{}

	// 高低要一个map 还有 ELF
	fake_events_map := &manager.Map{
		Name: "fake_events",
	}
	maps = append(maps, fake_events_map)

	this.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}
	return nil
}

func (this *PerfMMAP) setupManagerOptions() {
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

func (this *PerfMMAP) Start() error {
	return this.start()
}

func (this *PerfMMAP) Clone() IModule {
	mod := new(PerfMMAP)
	mod.name = this.name
	mod.mType = this.mType
	return mod
}

func (this *PerfMMAP) start() error {
	err := this.setupManager()
	if err != nil {
		return err
	}
	this.setupManagerOptions()

	var bpfFileName = filepath.Join("user/assets", this.hookBpfFile)
	byteBuf, err := assets.Asset(bpfFileName)

	if err != nil {
		return fmt.Errorf("%s\tcouldn't find asset %v .", this.Name(), err)
	}

	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}

	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *PerfMMAP) initDecodeFun() error {
	map_name := "fake_events"
	FakeEventsMap, found, err := this.bpfManager.GetMap(map_name)
	if err != nil {
		return err
	}
	if !found {
		return errors.New(fmt.Sprintf("cannot find map:%s", map_name))
	}

	this.eventMaps = append(this.eventMaps, FakeEventsMap)
	commonEvent := &event.CommonEvent{}
	this.eventFuncMaps[FakeEventsMap] = commonEvent

	return nil
}

func (this *PerfMMAP) Events() []*ebpf.Map {
	return this.eventMaps
}

func (this *PerfMMAP) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func init() {
	mod := &PerfMMAP{}
	mod.name = MODULE_NAME_PERF
	mod.mType = PROBE_TYPE_PERF
	Register(mod)
}
