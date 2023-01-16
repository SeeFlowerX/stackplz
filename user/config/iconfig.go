package config

const MAX_COUNT = 20

type IConfig interface {
	GetSConfig() *SConfig
	SetDebug(bool)
	Info() string
}

type SConfig struct {
	Uid         uint32
	Pid         uint32
	Tid         uint32
	UnwindStack bool
	ShowRegs    bool
	GetLR       bool
	GetPC       bool
	RegName     string
	Debug       bool
	Quiet       bool
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
