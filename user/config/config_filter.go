package config

type BaseFilter struct {
	uid                 uint32
	pid                 uint32
	tid                 uint32
	tids_blacklist_mask uint32
	tids_blacklist      [MAX_COUNT]uint32
	pids_blacklist_mask uint32
	pids_blacklist      [MAX_COUNT]uint32
}

type UprobeStackFilter struct {
	BaseFilter
}

type SyscallFilter struct {
	is_32bit               uint32
	after_read             uint32
	syscall_mask           uint32
	syscall                [MAX_COUNT]uint32
	syscall_blacklist_mask uint32
	syscall_blacklist      [MAX_COUNT]uint32
}

type CommonFilter struct {
	uid             uint32
	pid             uint32
	tid             uint32
	blacklist_pids  uint32
	blacklist_tids  uint32
	blacklist_comms uint32
	is_32bit        uint32
}

type ConfigMap struct {
	filter_mode  uint32
	stackplz_pid uint32
}

func (this *SyscallFilter) SetArch(is_32bit bool) {
	if is_32bit {
		this.is_32bit = 1
	} else {
		this.is_32bit = 0
	}
}

func (this *SyscallFilter) SetAfterRead(after_read bool) {
	if after_read {
		this.after_read = 1
	} else {
		this.after_read = 0
	}
}
