package config

type TargetConfig struct {
    Name        string
    Uid         uint64
    LibraryDirs []string
    DataDir     string
    Abi         string
}

func NewTargetConfig() *TargetConfig {
    config := &TargetConfig{}
    return config
}
