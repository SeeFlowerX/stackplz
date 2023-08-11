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
	"github.com/cilium/ebpf/btf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type PerfBRK struct {
	Module
	mconf             *config.ModuleConfig
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
	hookBpfFile       string
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
	this.hookBpfFile = "perf_mmap.o"
	return nil
}
func (this *PerfBRK) setupManager() error {
	maps := []*manager.Map{}
	probes := []*manager.Probe{}

	events_map := &manager.Map{
		Name: "brk_events",
	}
	maps = append(maps, events_map)

	// perf_probe := &manager.Probe{
	// 	Section:      "perf_event",
	// 	EbpfFuncName: "perf_event_handler",
	// }
	// probes = append(probes, perf_probe)

	this.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}
	return nil
}

func (this *PerfBRK) setupManagerOptions() {
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

func (this *PerfBRK) start() error {
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

func (this *PerfBRK) initDecodeFun() (err error) {
	// err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
	// 	Cur: math.MaxUint64,
	// 	Max: math.MaxUint64,
	// })
	// if err != nil {
	// 	return errors.New(fmt.Sprintf("error:%v , couldn't adjust RLIMIT_MEMLOCK", err))
	// }
	// events, err := ebpf.NewMap(&ebpf.MapSpec{
	// 	Name: "brk_events",
	// 	Type: ebpf.PerfEventArray,
	// })
	// if err != nil {
	// 	return err
	// }

	map_name := "brk_events"
	BrkEventsMap, found, err := this.bpfManager.GetMap(map_name)
	if err != nil {
		return err
	}
	if !found {
		return errors.New(fmt.Sprintf("cannot find map:%s", map_name))
	}

	this.eventMaps = append(this.eventMaps, BrkEventsMap)
	commonEvent := &event.CommonEvent{}
	commonEvent.SetConf(this.mconf)
	this.eventFuncMaps[BrkEventsMap] = commonEvent

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
