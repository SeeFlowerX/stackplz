package config

type GlobalConfig struct {
    Prepare       bool
    Name          string
    Uid           uint64
    Pid           uint64
    UnwindStack   bool
    ShowRegs      bool
    GetLR         bool
    GetPC         bool
    TidsBlacklist string
    Debug         bool
    Quiet         bool
    LogFile       string
    Library       string
    Symbol        string
    Offset        uint64
    RegName       string
    SysCall       string
    Config        string
}

func NewGlobalConfig() *GlobalConfig {
    config := &GlobalConfig{}
    return config
}

func (this *GlobalConfig) Check() error {

    return nil
}
