//go:build !forarm
// +build !forarm

package config

func (this *GlobalConfig) Is32Bit() bool {
    return false
}

func (this *GlobalConfig) GetSyscallConfigFile() string {
    return "user/config/config_syscall_aarch64.json"
}

func (this *GlobalConfig) InitLibraryDirs() {
    // 设置常见的系统库路径 注意要检查是不是符号链接
    lib_search_path := []string{
        "/system/lib64",
        "/apex/com.android.art/lib64",
        "/apex/com.android.conscrypt/lib64",
        "/apex/com.android.runtime/bin",
        "/apex/com.android.runtime/lib64/bionic",
    }
    this.LibraryDirs = append(this.LibraryDirs, lib_search_path...)
}
