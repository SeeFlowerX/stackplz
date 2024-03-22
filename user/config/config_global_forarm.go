//go:build forarm
// +build forarm

package config

func (this *GlobalConfig) Is32Bit() bool {
    return true
}

func (this *GlobalConfig) GetSyscallConfigFile() string {
    return "user/config/config_syscall_aarch32.json"
}

func (this *GlobalConfig) InitLibraryDirs() {
    // 实测 arm uprobe 存在无法解决的问题
    lib_search_path := []string{
        "/system/lib",
        "/apex/com.android.art/lib",
        "/apex/com.android.conscrypt/lib",
        "/apex/com.android.runtime/bin",
        "/apex/com.android.runtime/lib/bionic",
    }
    this.LibraryDirs = append(this.LibraryDirs, lib_search_path...)
}
