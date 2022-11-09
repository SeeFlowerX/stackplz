package config

type IConfig interface {
    Check() error //检测配置合法性
    GetUid() uint64
    GetDebug() bool
    GetUnwindStack() bool
    GetShowRegs() bool
    GetConfig() string
    SetUid(uint64)
    SetDebug(bool)
    SetUnwindStack(bool)
    SetShowRegs(bool)
    SetConfig(string)
}

type eConfig struct {
    Pid         uint64
    Uid         uint64
    Debug       bool
    UnwindStack bool
    ShowRegs    bool
    Config      string
}

func (this *eConfig) GetUid() uint64 {
    return this.Uid
}

func (this *eConfig) GetDebug() bool {
    return this.Debug
}

func (this *eConfig) GetUnwindStack() bool {
    return this.UnwindStack
}

func (this *eConfig) GetShowRegs() bool {
    return this.ShowRegs
}

func (this *eConfig) GetConfig() string {
    return this.Config
}

func (this *eConfig) SetUid(uid uint64) {
    this.Uid = uid
}

func (this *eConfig) SetDebug(debug bool) {
    this.Debug = debug
}

func (this *eConfig) SetUnwindStack(unwindStack bool) {
    this.UnwindStack = unwindStack
}

func (this *eConfig) SetShowRegs(show_regs bool) {
    this.ShowRegs = show_regs
}

func (this *eConfig) SetConfig(config string) {
    this.Config = config
}
