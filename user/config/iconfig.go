package config

import "log"

const MAX_COUNT = 20
const MAX_WATCH_PROC_COUNT = 256

// stackplz => 737461636b706c7a
const MAGIC_UID = 0x73746163
const MAGIC_PID = 0x6b706c7a
const MAGIC_TID = 0x61636b70

// syscall => 73797363616c6c
const MAGIC_SYSCALL = 0x73797363

type IConfig interface {
	GetSConfig() *SConfig
	SetDebug(bool)
	Info() string
}

type SConfig struct {
	SelfPid     uint32
	FilterMode  uint32
	Uid         uint32
	Pid         uint32
	Tid         uint32
	UnwindStack bool
	ShowRegs    bool
	GetLR       bool
	GetPC       bool
	RegName     string
	ExternalBTF string
	Debug       bool
	Quiet       bool
	Is32Bit     bool
	Buffer      uint32
	logger      *log.Logger
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
