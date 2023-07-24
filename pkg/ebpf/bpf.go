package ebpf

import (
    "fmt"

    "golang.org/x/sys/unix"
)

// CONFIG CHECK ITEMS
var (
    configCheckItems = []string{
        "CONFIG_BPF",
        "CONFIG_UPROBES",
        "CONFIG_ARCH_SUPPORTS_UPROBES",
    }
)

type UnameInfo struct {
    SysName    string
    Nodename   string
    Release    string
    Version    string
    Machine    string
    Domainname string
}

func getOSUnamer() (*UnameInfo, error) {
    u := unix.Utsname{}
    e := unix.Uname(&u)
    if e != nil {
        return nil, e
    }
    ui := UnameInfo{}
    ui.SysName = charsToString(u.Sysname)
    ui.Nodename = charsToString(u.Nodename)
    ui.Release = charsToString(u.Release)
    ui.Version = charsToString(u.Version)
    ui.Machine = charsToString(u.Machine)
    ui.Domainname = charsToString(u.Domainname)

    return &ui, nil
}

func charsToString(ca [65]byte) string {
    s := make([]byte, len(ca))
    var lens int
    for ; lens < len(ca); lens++ {
        if ca[lens] == 0 {
            break
        }
        s[lens] = uint8(ca[lens])
    }
    return string(s[0:lens])
}

var KernelConfig map[string]string
var HasEnableBPF bool = true
var HasEnableBTF bool = false

func CheckKernelConfig() error {

    KernelConfig, e := GetSystemConfig()
    if e != nil {
        return fmt.Errorf("Kernel config read failed, error:%v", e)
    }

    for _, item := range configCheckItems {
        bc, found := KernelConfig[item]
        if !found {
            HasEnableBPF = false
            return fmt.Errorf("Config not found,  item:%s.", item)
        }
        if bc != "y" {
            HasEnableBPF = false
            return fmt.Errorf("Config disabled, item :%s.", item)
        }
    }

    bc, found := KernelConfig[CONFIG_DEBUG_INFO_BTF]
    if found && bc == "y" {
        HasEnableBTF = true
    }
    return nil
}
