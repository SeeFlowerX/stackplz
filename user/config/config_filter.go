package config

type ConfigMap struct {
	filter_mode  uint32
	stackplz_pid uint32
}

type CommonFilter struct {
	// is_32bit              uint32
	// uid                   uint32
	// pid                   uint32
	// tid                   uint32
	pid_list [MAX_WATCH_PROC_COUNT]uint32
	// blacklist_pids        [MAX_COUNT]uint32
	// blacklist_tids        [MAX_COUNT]uint32
	thread_name_whitelist uint32
	trace_uid_group       uint32
	signal                uint32
}

type ThreadFilter struct {
	ThreadName [16]byte
}

type RevFilter struct {
	RevString [32]byte
}

type SyscallFilter struct {
	is_32bit       uint32
	trace_mode     uint32
	whitelist_mode uint32
	blacklist_mode uint32
}

func (this *SyscallFilter) SetArch(is_32bit bool) {
	if is_32bit {
		this.is_32bit = 1
	} else {
		this.is_32bit = 0
	}
}

func (this *SyscallFilter) SetTraceMode(mode uint32) {
	this.trace_mode = mode
}

func (this *SyscallFilter) GetTraceMode() uint32 {
	return this.trace_mode
}

func (this *SyscallFilter) SetWhitelistMode(flag bool) {
	if flag {
		this.whitelist_mode = 1
	} else {
		this.whitelist_mode = 0
	}
}

func (this *SyscallFilter) SetBlacklistMode(flag bool) {
	if flag {
		this.blacklist_mode = 1
	} else {
		this.blacklist_mode = 0
	}
}
