package config

type ConfigMap struct {
	filter_mode  uint32
	stackplz_pid uint32
}

type CommonFilter struct {
	is_32bit              uint32
	uid                   uint32
	pid                   uint32
	tid                   uint32
	pid_list              [MAX_WATCH_PROC_COUNT]uint32
	blacklist_pids        [MAX_COUNT]uint32
	blacklist_tids        [MAX_COUNT]uint32
	thread_name_whitelist uint32
	trace_isolated        uint32
	signal                uint32
}

type ThreadFilter struct {
	ThreadName [16]byte
}

type RevFilter struct {
	RevString [32]byte
}

type SyscallFilter struct {
	is_32bit               uint32
	syscall_all            uint32
	syscall_mask           uint32
	syscall                [MAX_COUNT]uint32
	syscall_blacklist_mask uint32
	syscall_blacklist      [MAX_COUNT]uint32
}

func (this *SyscallFilter) SetArch(is_32bit bool) {
	if is_32bit {
		this.is_32bit = 1
	} else {
		this.is_32bit = 0
	}
}

func (this *SyscallFilter) SetHookALL(all bool) {
	if all {
		this.syscall_all = 1
	} else {
		this.syscall_all = 0
	}
}
