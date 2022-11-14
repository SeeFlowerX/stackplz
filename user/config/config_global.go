package config

type GlobalConfig struct {
    Quiet      bool
    Prepare    bool
    Name       string
    Debug      bool
    Uid        uint64
    Pid        uint64
    LoggerFile string
    ExecPath   string
}

func NewGlobalConfig() *GlobalConfig {
    config := &GlobalConfig{}
    return config
}

func (this *GlobalConfig) Check() error {

    return nil
}
