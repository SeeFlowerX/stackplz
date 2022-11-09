package config

type StackConfig struct {
    eConfig
    Libpath string
    Symbol  string
    Offset  uint64
    Config  string
}

func NewStackConfig() *StackConfig {
    config := &StackConfig{}
    return config
}

func (this *StackConfig) Check() error {

    return nil
}
