package event_parser

import (
	"encoding/binary"
	"io"
	"log"
	"os"
	"stackplz/user/common"
	"stackplz/user/config"
	"stackplz/user/event"

	"github.com/cilium/ebpf/perf"
)

func NewEventParser() *EventParser {
	parser := &EventParser{}
	return parser
}

type EventParser struct {
	logger *log.Logger
	mconf  *config.ModuleConfig
}

func (this *EventParser) SetLogger(logger *log.Logger) {
	this.logger = logger
}

func (this *EventParser) SetConf(mconf *config.ModuleConfig) {
	this.mconf = mconf
}

func (this *EventParser) ParseDump(dump_name string) {
	if dump_name == "" {
		return
	}
	dir, _ := os.Getwd()
	dump_path := dir + "/" + dump_name
	// 提前打开文件
	f, err := os.Open(dump_path)
	if err != nil {
		panic("open dump file failed...")
	}

	for {
		var total_len uint32
		var event_index uint8
		var rec_type uint32
		var rec_len uint32
		if err = binary.Read(f, binary.LittleEndian, &total_len); err != nil {
			// 理想情况下应该在这里退出
			if err == io.EOF {
				break
			}
			panic(err)
		}
		if err = binary.Read(f, binary.LittleEndian, &event_index); err != nil {
			panic(err)
		}
		if err = binary.Read(f, binary.LittleEndian, &rec_type); err != nil {
			panic(err)
		}
		if err = binary.Read(f, binary.LittleEndian, &rec_len); err != nil {
			panic(err)
		}
		// this.logger.Printf("len:%d event:%d type:%d rec_len:%d\n", total_len, event_index, rec_type, rec_len)
		rec_raw := make([]byte, rec_len)
		if err = binary.Read(f, binary.LittleEndian, &rec_raw); err != nil {
			panic(err)
		}
		// this.logger.Printf("rec_raw:\n%s", util.HexDumpGreen(rec_raw))
		rec := perf.Record{}
		rec.RawSample = rec_raw
		rec.RecordType = rec_type

		rec.ExtraOptions = &perf.ExtraPerfOptions{
			UnwindStack:       this.mconf.UnwindStack,
			ShowRegs:          this.mconf.ShowRegs,
			BrkAddr:           this.mconf.BrkAddr,
			BrkLen:            this.mconf.BrkLen,
			BrkType:           this.mconf.BrkType,
			Sample_stack_user: this.mconf.StackSize,
		}

		var te event.IEventStruct
		switch event_index {
		case common.COMMON_EVENT:
			te = &event.CommonEvent{}
		case common.BRK_EVENT:
			te = &event.BrkEvent{}
		case common.UPROBE_EVENT:
			te = &event.UprobeEvent{}
		case common.SYSCALL_EVENT:
			te = &event.SyscallEvent{}
		default:
			panic("unknown event...")
		}
		te.SetLogger(this.logger)
		te.SetConf(this.mconf)
		te.SetRecord(rec)
		data_e, err := te.ParseEvent()
		if err != nil {
			panic(err)
		}
		this.logger.Println(data_e.String())
	}
	os.Exit(0)
}
