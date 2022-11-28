package config

type StackConfig struct {
    UnwindStack bool
    ShowRegs    bool
    Library     string
    Symbol      string
    Offset      uint64
    RegName     string
    Config      string
}

func NewStackConfig() *StackConfig {
    config := &StackConfig{}
    return config
}

func (this *StackConfig) Check() error {

    return nil
}
