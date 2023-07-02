package module

const (
    PROBE_TYPE_UPROBE     = "uprobe"
    PROBE_TYPE_KPROBE     = "kprobe"
    PROBE_TYPE_TRACEPOINT = "tracepoint"
    PROBE_TYPE_PERF       = "perf"
)

const (
    MODULE_NAME_PERF    = "PerfMod"
    MODULE_NAME_STACK   = "StackMod"
    MODULE_NAME_SYSCALL = "SyscallMod"
)
