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
    // 设置常见的系统库路径 注意要检查是不是符号链接
    lib_search_path := []string{
        "/system/lib64",
        "/apex/com.android.art/lib64",
        "/apex/com.android.conscrypt/lib64",
        "/apex/com.android.runtime/lib64/bionic",
    }
    config.LibraryDirs = append(config.LibraryDirs, lib_search_path...)
    return config
}
