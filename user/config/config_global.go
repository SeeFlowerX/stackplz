package config

import (
    "archive/zip"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "stackplz/assets"
    "strings"

    "golang.org/x/exp/slices"
)

type GlobalConfig struct {
    ExecPath    string
    TragetArch  string
    Name        string
    Uid         string
    NoUid       string
    Pid         string
    NoPid       string
    Tid         string
    NoTid       string
    TName       string
    NoTName     string
    FullTName   bool
    ArgFilter   []string
    Color       bool
    FmtJson     bool
    UnwindStack bool
    ManualStack bool
    StackSize   uint32
    ShowRegs    bool
    GetOff      bool
    AutoResume  bool
    KillSignal  string
    TKillSignal string
    Rpc         bool
    RpcPath     string
    Debug       bool
    Quiet       bool
    Buffer      uint32
    MaxOp       uint32
    BrkPid      int
    BrkAddr     string
    BrkLib      string
    BrkLen      uint64
    LogFile     string
    DumpFile    string
    ParseFile   string
    DataDir     string
    LibraryDirs []string
    HookPoint   []string
    Library     string
    RegName     string
    DumpRet     bool
    DumpHex     bool
    ShowPC      bool
    ShowTime    bool
    ShowUid     bool
    NoCheck     bool
    Btf         bool
    ExternalBTF string
    SysCall     string
    NoSysCall   string
    ConfigFiles []string
}

func NewGlobalConfig() *GlobalConfig {
    return &GlobalConfig{}
}

func (this *GlobalConfig) RestoreAssets() error {
    check_list := []string{"libstackplz.so", "libunwindstack.so"}
    for _, check_file := range check_list {
        check_path := "preload_libs" + "/" + check_file
        check_info, err := os.Stat(this.ExecPath + "/" + check_path)
        if err != nil {
            if os.IsNotExist(err) {
                err = assets.RestoreAssets(this.ExecPath, "preload_libs")
                if err != nil {
                    return fmt.Errorf("RestoreAssets preload_libs failed, %v", err)
                }
                return nil
            }
        }
        info, err := assets.AssetInfo(check_path)
        if info.Size() != check_info.Size() {
            err = assets.RestoreAssets(this.ExecPath, "preload_libs")
            if err != nil {
                return fmt.Errorf("RestoreAssets preload_libs failed, %v", err)
            }
            return nil
        }
    }
    return nil
}
func (this *GlobalConfig) InitLibraryDirs() {
    // 设置常见的系统库路径 注意要检查是不是符号链接
    this.LibraryDirs = []string{}
    switch this.TragetArch {
    case "aarch64":
        lib_search_path := []string{
            "/system/lib64",
            "/apex/com.android.art/lib64",
            "/apex/com.android.conscrypt/lib64",
            "/apex/com.android.runtime/bin",
            "/apex/com.android.runtime/lib64/bionic",
        }
        this.LibraryDirs = append(this.LibraryDirs, lib_search_path...)
    case "arm", "aarch32":
        // 实测 arm uprobe 存在无法解决的问题
        lib_search_path := []string{
            "/system/lib",
            "/apex/com.android.art/lib",
            "/apex/com.android.conscrypt/lib",
            "/apex/com.android.runtime/bin",
            "/apex/com.android.runtime/lib/bionic",
        }
        this.LibraryDirs = append(this.LibraryDirs, lib_search_path...)
    default:
        panic(fmt.Sprintf("arch %s not supported", this.TragetArch))
    }
}

func (this *GlobalConfig) ParseArgFilter() {
    for _, arg_filter := range this.ArgFilter {
        AddFilter(arg_filter)
    }
}

func (this *GlobalConfig) FindLibInApk(library string, sconfig *StackUprobeConfig) (err error) {

    // 在常规的情况下都没找到 尝试在 apk 文件中搜索 split apk 安装后的名字都是 split_config 开头
    // - base.apk!/lib/arm64-v8a/
    // - split_config.arm64_v8a.apk!lib/arm64-v8a/
    // 目前不管 armeabi-v7a
    // - base.apk!/lib/armeabi-v7a/
    // - split_config.armeabi_v7a.apk!lib/armeabi-v7a/

    lib_search_paths := []string{"lib/arm64-v8a"}
    for _, apk_path := range this.LibraryDirs {
        // 确保只检查 .apk
        if !strings.HasSuffix(apk_path, ".apk") {
            continue
        }
        // 读取 .apk
        zf, err := zip.OpenReader(apk_path)
        if err != nil {
            return err
        }
        for _, f := range zf.File {
            for _, search_path := range lib_search_paths {
                // 这里是存在重复的可能的 不过不考虑这种情况
                check_path := search_path + "/" + library
                if f.Name == check_path {
                    srcFile, err := f.Open()
                    if err != nil {
                        return err
                    }
                    // apk 路径作为最终的 uprobe 注册文件
                    sconfig.RealFilePath = apk_path
                    // 将文件释放到和stackplz一个目录 用于 apk + symbol
                    sconfig.LibPath = filepath.Join(this.ExecPath, library)
                    dstFile, err := os.OpenFile(sconfig.LibPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
                    if err != nil {
                        panic(err)
                    }
                    if _, err := io.Copy(dstFile, srcFile); err != nil {
                        panic(err)
                    }
                    dstFile.Close()
                    srcFile.Close()
                    offset, err := f.DataOffset()
                    if err != nil {
                        return err
                    }
                    sconfig.NonElfOffset = uint64(offset)
                    return nil
                }
            }
        }
    }

    return errors.New(fmt.Sprintf("can not find %s in any apk", library))
}

func (this *GlobalConfig) Parse_Libinfo(library string, sconfig *StackUprobeConfig) (err error) {
    sconfig.LibPath = ""
    sconfig.NonElfOffset = 0
    search_paths := this.LibraryDirs

    if library == "" {
        return errors.New("empty library path")
    }
    // 以 / 开头的认为是完整路径 否则在提供的路径中查找
    if strings.HasPrefix(library, "/") {
        if _, err := os.Stat(library); err != nil {
            // 出现异常 提示对应的错误信息
            return err
        }
        sconfig.LibPath = library
    } else {
        var full_paths []string
        for _, search_path := range search_paths {
            // 去掉末尾可能存在的 /
            check_path := strings.TrimRight(search_path, "/") + "/" + library
            _, err := os.Stat(check_path)
            if err != nil {
                // 这里在debug模式下打印出来
                continue
            }
            path_info, err := os.Lstat(check_path)
            if err != nil {
                continue
            }
            if path_info.Mode()&os.ModeSymlink != 0 {
                real_path, err := filepath.EvalSymlinks(check_path)
                if err != nil {
                    continue
                }
                check_path = real_path
            }
            if !slices.Contains(full_paths, check_path) {
                full_paths = append(full_paths, check_path)
            }
        }
        if len(full_paths) == 0 {
            err = this.FindLibInApk(library, sconfig)
            if err == nil {
                return err
            }
            // 没找到
            return fmt.Errorf("can not find %s in these paths\n\t%s", library, strings.Join(search_paths[:], "\n\t"))
        }
        // 在已有的搜索路径下可能存在多个同名的库 提示用户指定全路径
        if len(full_paths) > 1 {
            return fmt.Errorf("find %d libs with the same name\n%s", len(full_paths), strings.Join(full_paths[:], "\n\t"))
        }
        // 修正为完整路径
        sconfig.LibPath = full_paths[0]
    }
    sconfig.RealFilePath = sconfig.LibPath
    return err
}
