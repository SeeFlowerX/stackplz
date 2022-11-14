package config

type IConfig interface {
	GetSConfig() *SConfig
	SetDebug(bool)
	Info() string
}

type SConfig struct {
	Uid         uint64
	UnwindStack bool
	ShowRegs    bool
	Debug       bool
}

func (this *SConfig) SetDebug(debug bool) {
	this.Debug = debug
}

func (this *SConfig) Info() string {
	return "DefaultInfo"
}

func (this *SConfig) GetSConfig() *SConfig {
	return this
}
