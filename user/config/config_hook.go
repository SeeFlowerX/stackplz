package config

import (
    "fmt"
    "os"
    "stackplz/pkg/util"
    "strings"
)

type ProbeConfig struct {
    SConfig
    LibName string
    Library string
    Symbol  string
    // Uid     uint64
    Offset uint64
    // UnwindStack bool
    // ShowRegs    bool
}

func NewProbeConfig() *ProbeConfig {
    config := &ProbeConfig{}
    return config
}

func (this *ProbeConfig) Info() string {
    // hook点信息
    if this.Offset == 0 {
        return fmt.Sprintf("%s + %s", this.LibName, this.Symbol)
    } else {
        return fmt.Sprintf("%s + 0x%x", this.LibName, this.Offset)
    }
}

func (this *ProbeConfig) Check() error {
    // 对每一个hook配置进行检查
    // 1. 要有完整的库路径
    // 2. 要么指定符号 要么指定偏移
    _, err := os.Stat(this.Library)
    if err != nil {
        return err
    }

    if this.Symbol == "" && this.Offset == 0 {
        return fmt.Errorf("need symbol or offset, Library:%s\n", this.Library)
    }

    if this.Symbol != "" && this.Offset > 0 {
        return fmt.Errorf("just symbol or offset, not all of them\n")
    }

    // 虽然前面不允许用户同时设置offset和symbol 但是ebpf库必须要有一个symbol 于是这里随机下就好了
    if this.Offset > 0 {
        this.Symbol = util.RandStringBytes(8)
    }
    parts := strings.Split(this.Library, "/")
    this.LibName = parts[len(parts)-1]
    return nil
}

func (this *ProbeConfig) GetFilter() StackFilter {
    filter := StackFilter{
        uid:                uint32(this.Uid),
        pid:                uint32(this.Pid),
        tid_blacklist_mask: this.TidBlacklistMask,
        tid_blacklist:      this.TidBlacklist,
    }
    return filter
}
