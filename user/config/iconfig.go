package config

import (
	"errors"
	"fmt"
	"log"
)

const MAX_COUNT = 20
const MAX_WATCH_PROC_COUNT = 256

// stackplz => 737461636b706c7a
const MAGIC_UID = 0x73746163
const MAGIC_PID = 0x6b706c7a
const MAGIC_TID = 0x61636b70

type IConfig interface {
	GetSConfig() *SConfig
	SetDebug(bool)
	Info() string
}

type SConfig struct {
	SelfPid       uint32
	FilterMode    uint32
	Uid           uint32
	Pid           uint32
	Tid           uint32
	TraceIsolated bool
	HideRoot      bool
	UprobeSignal  uint32
	UnwindStack   bool
	StackSize     uint32
	ShowRegs      bool
	GetOff        bool
	RegName       string
	ExternalBTF   string
	Debug         bool
	Is32Bit       bool
	Buffer        uint32
	BrkAddr       uint64
	BrkType       uint32
	Color         bool
	DumpHex       bool
	logger        *log.Logger
}

func (this *SConfig) SetLogger(logger *log.Logger) {
	this.logger = logger
}

func (this *SConfig) SetDebug(debug bool) {
	this.Debug = debug
}

func (this *SConfig) Info() string {
	panic("SConfig.Info() not implemented yet")
}

func (this *SConfig) GetSConfig() *SConfig {
	return this
}

const MAX_BUF_READ_SIZE uint32 = 4096

const (
	REG_ARM64_X0 uint32 = iota
	REG_ARM64_X1
	REG_ARM64_X2
	REG_ARM64_X3
	REG_ARM64_X4
	REG_ARM64_X5
	REG_ARM64_X6
	REG_ARM64_X7
	REG_ARM64_X8
	REG_ARM64_X9
	REG_ARM64_X10
	REG_ARM64_X11
	REG_ARM64_X12
	REG_ARM64_X13
	REG_ARM64_X14
	REG_ARM64_X15
	REG_ARM64_X16
	REG_ARM64_X17
	REG_ARM64_X18
	REG_ARM64_X19
	REG_ARM64_X20
	REG_ARM64_X21
	REG_ARM64_X22
	REG_ARM64_X23
	REG_ARM64_X24
	REG_ARM64_X25
	REG_ARM64_X26
	REG_ARM64_X27
	REG_ARM64_X28
	REG_ARM64_X29
	REG_ARM64_LR
	REG_ARM64_SP
	REG_ARM64_PC
	REG_ARM64_MAX
)

var RegsMagicMap map[string]uint32 = map[string]uint32{
	"x0":  REG_ARM64_X0,
	"x1":  REG_ARM64_X1,
	"x2":  REG_ARM64_X2,
	"x3":  REG_ARM64_X3,
	"x4":  REG_ARM64_X4,
	"x5":  REG_ARM64_X5,
	"x6":  REG_ARM64_X6,
	"x7":  REG_ARM64_X7,
	"x8":  REG_ARM64_X8,
	"x9":  REG_ARM64_X9,
	"x10": REG_ARM64_X10,
	"x11": REG_ARM64_X11,
	"x12": REG_ARM64_X12,
	"x13": REG_ARM64_X13,
	"x14": REG_ARM64_X14,
	"x15": REG_ARM64_X15,
	"x16": REG_ARM64_X16,
	"x17": REG_ARM64_X17,
	"x18": REG_ARM64_X18,
	"x19": REG_ARM64_X19,
	"x20": REG_ARM64_X20,
	"x21": REG_ARM64_X21,
	"x22": REG_ARM64_X22,
	"x23": REG_ARM64_X23,
	"x24": REG_ARM64_X24,
	"x25": REG_ARM64_X25,
	"x26": REG_ARM64_X26,
	"x27": REG_ARM64_X27,
	"x28": REG_ARM64_X28,
	"x29": REG_ARM64_X29,
	"lr":  REG_ARM64_LR,
	"sp":  REG_ARM64_SP,
	"pc":  REG_ARM64_PC,
}

func ParseAsReg(reg string) (uint32, error) {
	value, ok := RegsMagicMap[reg]
	if ok {
		return value, nil
	} else {
		return 0, errors.New(fmt.Sprintf("ParseAsReg failed =>%s<=", reg))
	}
}
