package config

type GlobalConfig struct {
    Prepare          bool
    Name             string
    Uid              uint32
    Pid              uint32
    Tid              uint32
    Color            bool
    UnwindStack      bool
    ShowRegs         bool
    GetLR            bool
    GetPC            bool
    TidsBlacklist    string
    PidsBlacklist    string
    Debug            bool
    Quiet            bool
    AfterRead        bool
    Is32Bit          bool
    Buffer           uint32
    LogFile          string
    DataDir          string
    LibraryDirs      []string
    Library          string
    Symbol           string
    Offset           uint64
    RegName          string
    DumpHex          string
    DumpLen          uint32
    SysCall          string
    SysCallBlacklist string
    Config           string
    CanReadUser      bool
}

func NewGlobalConfig() *GlobalConfig {
    config := &GlobalConfig{}
    // 默认设置 目的是为了后续允许加入对 uid=0 也就是 root 进程的追踪
    config.Uid = MAGIC_UID
    config.Pid = MAGIC_PID
    config.Tid = MAGIC_TID
    return config
}

func (this *GlobalConfig) Check() error {

    return nil
}
