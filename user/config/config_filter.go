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
	BaseFilter
	is_32bit uint32
	// try_bypass             uint32
	after_read             uint32
	syscall_mask           uint32
	syscall                [MAX_COUNT]uint32
	syscall_blacklist_mask uint32
	syscall_blacklist      [MAX_COUNT]uint32
}

type CommonFilter struct {
	uid      uint32
	pid      uint32
	tid      uint32
	is_32bit uint32
}

type ConfigMap struct {
	stackplz_pid uint32
}

type VmaInfoFilter struct {
	uid uint32
	pid uint32
}

func (this *SyscallFilter) SetUid(uid uint32) {
	this.uid = uid
}

func (this *SyscallFilter) SetPid(pid uint32) {
	this.pid = pid
}

// func (this *SyscallFilter) SetSysCall(syscall string, systable_config SysTableConfig) error {
// 	items := strings.Split(syscall, ",")
// 	if len(items) > MAX_COUNT {
// 		return fmt.Errorf("max syscall whitelist count is %d, provided count:%d", MAX_COUNT, len(items))
// 	}
// 	for i, v := range items {
// 		nr, err := systable_config.GetNR(v)
// 		if err != nil {
// 			return err
// 		}
// 		this.syscall[i] = uint32(nr)
// 		this.syscall_mask |= (1 << i)
// 	}
// 	return nil
// }

// func (this *SyscallFilter) SetSysCallBlacklist(syscall_blacklist string, systable_config SysTableConfig) error {
// 	items := strings.Split(syscall_blacklist, ",")
// 	if len(items) > MAX_COUNT {
// 		return fmt.Errorf("max syscall blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
// 	}
// 	for i, v := range items {
// 		nr, err := systable_config.GetNR(v)
// 		if err != nil {
// 			return err
// 		}
// 		this.syscall_blacklist[i] = uint32(nr)
// 		this.syscall_blacklist_mask |= (1 << i)
// 	}
// 	return nil
// }

// func (this *SyscallFilter) SetTidBlacklist(tids_blacklist string) error {
// 	items := strings.Split(tids_blacklist, ",")
// 	if len(items) > MAX_COUNT {
// 		return fmt.Errorf("max tid blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
// 	}
// 	for i, v := range items {
// 		value, _ := strconv.ParseUint(v, 10, 32)
// 		this.tids_blacklist[i] = uint32(value)
// 		this.tids_blacklist_mask |= (1 << i)
// 	}
// 	return nil
// }

func (this *SyscallFilter) SetArch(is_32bit bool) {
	if is_32bit {
		this.is_32bit = 1
	} else {
		this.is_32bit = 0
	}
}

// func (this *SyscallFilter) SetByPass(try_bypass bool) {
// 	if try_bypass {
// 		this.try_bypass = 1
// 	} else {
// 		this.try_bypass = 0
// 	}
// }

func (this *SyscallFilter) SetAfterRead(after_read bool) {
	if after_read {
		this.after_read = 1
	} else {
		this.after_read = 0
	}
}
