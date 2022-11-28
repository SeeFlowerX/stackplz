package config

type StackFilter struct {
	uid uint32
	pid uint32
}

type SyscallFilter struct {
	uid uint32
	pid uint32
	nr  uint32
}

type IConfig interface {
	GetSConfig() *SConfig
	SetDebug(bool)
	Info() string
}

type SConfig struct {
	Uid         uint64
	Pid         uint64
	UnwindStack bool
	ShowRegs    bool
	RegName     string
	Debug       bool
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
