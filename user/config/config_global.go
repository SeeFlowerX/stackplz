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
    FmtJson      bool
    UnwindStack  bool
    ManualStack  bool
    StackSize    uint32
    ShowRegs     bool
    GetOff       bool
    UprobeSignal string
    Rpc          bool
    RpcPath      string
    Debug        bool
    Quiet        bool
    Buffer       uint32
    BrkPid       int
    BrkAddr      string
    BrkLib       string
    BrkLen       uint64
    LogFile      string
    DataDir      string
    LibraryDirs  []string
    HookPoint    []string
    Library      string
    RegName      string
    DumpRet      bool
    DumpHex      bool
    ShowTime     bool
    ShowUid      bool
    NoCheck      bool
    Btf          bool
    ExternalBTF  string
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
        "/apex/com.android.runtime/bin",
        "/apex/com.android.runtime/lib64/bionic",
    }
    config.LibraryDirs = append(config.LibraryDirs, lib_search_path...)
    return config
}
