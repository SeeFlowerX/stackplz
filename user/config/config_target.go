package config

type TargetConfig struct {
    Name             string
    Uid              uint64
    Pid              uint64
    TidsBlacklist     [MAX_COUNT]uint32
    TidsBlacklistMask uint32
    LibraryDirs      []string
    DataDir          string
    Abi              string
}

func NewTargetConfig() *TargetConfig {
    config := &TargetConfig{}
    return config
}
