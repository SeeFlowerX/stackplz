package config

type GlobalConfig struct {
    Prepare      bool
    Name         string
    Uid          string
    NoUid        string
    Pid          string
    NoPid        string
    Tid          string
    NoTid        string
    TName        string
    NoTName      string
    ArgFilter    []string
    Color        bool
    UnwindStack  bool
    StackSize    uint32
    ShowRegs     bool
    GetOff       bool
    HideRoot     bool
    UprobeSignal string
    Debug        bool
    Quiet        bool
    Buffer       uint32
    BrkAddr      string
    BrkLib       string
    LogFile      string
    DataDir      string
    LibraryDirs  []string
    HookPoint    []string
    Library      string
    RegName      string
    DumpHex      bool
    NoCheck      bool
    Btf          bool
    SysCall      string
    NoSysCall    string
}

func NewGlobalConfig() *GlobalConfig {
    config := &GlobalConfig{}
    return config
}
