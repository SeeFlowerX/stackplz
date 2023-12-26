package next

const (
	EBPF_PROG_NONE uint32 = iota
	EBPF_SYS_ENTER
	EBPF_SYS_EXIT
	EBPF_SYS_ALL
)
