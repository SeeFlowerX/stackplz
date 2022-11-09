package config

type IConfig interface {
    Check() error //检测配置合法性
    GetPid() uint64
    GetUid() uint64
    GetDebug() bool
    GetUnwindStack() bool
    GetShowRegs() bool
    SetPid(uint64)
    SetUid(uint64)
    SetDebug(bool)
    SetUnwindStack(bool)
    SetShowRegs(bool)
}

type eConfig struct {
    Pid         uint64
    Uid         uint64
    Debug       bool
    UnwindStack bool
    ShowRegs    bool
}

func (this *eConfig) GetPid() uint64 {
    return this.Pid
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

func (this *eConfig) SetPid(pid uint64) {
    this.Pid = pid
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
