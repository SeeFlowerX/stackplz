package next

import (
	"fmt"
)

type PointOpKeyConfig struct {
	OpCount   uint32
	OpKeyList [MAX_OP_COUNT]uint32
}

func (this *PointOpKeyConfig) AddPointArg(point_arg *PointArg) {
	for _, op_key := range point_arg.GetOpList() {
		this.OpKeyList[this.OpCount] = op_key
		this.OpCount++
		if this.OpCount == MAX_OP_COUNT {
			panic("PointOpKeyConfig->AddPointArg failed, need increase MAX_OP_COUNT")
		}
	}
}

type SyscallPoint struct {
	Nr             uint32
	Name           string
	EnterPointArgs []*PointArg
	ExitPointArgs  []*PointArg
}

func (this *SyscallPoint) GetEnterConfig() PointOpKeyConfig {
	config := PointOpKeyConfig{}
	for _, point_arg := range this.EnterPointArgs {
		config.AddPointArg(point_arg)
	}
	return config
}

func (this *SyscallPoint) GetExitConfig() PointOpKeyConfig {
	config := PointOpKeyConfig{}
	for _, point_arg := range this.ExitPointArgs {
		config.AddPointArg(point_arg)
	}
	return config
}

type SyscallPoints struct {
	points []*SyscallPoint
}

func (this *SyscallPoints) Dup(nr uint32, name string) bool {
	is_dup := false
	for _, point := range this.points {
		if point.Nr == nr {
			is_dup = true
			break
		} else if point.Name == name {
			is_dup = true
			break
		}
	}
	return is_dup
}

func (this *SyscallPoints) Add(point *SyscallPoint) {
	this.points = append(this.points, point)
}

func (this *SyscallPoints) GetPointByName(name string) *SyscallPoint {
	for _, point := range this.points {
		if point.Name == name {
			return point
		}
	}
	panic(fmt.Sprintf("GetPointByName failed for name %s", name))
}

func (this *SyscallPoints) GetPointByNR(nr uint32) *SyscallPoint {
	for _, point := range this.points {
		if point.Nr == nr {
			return point
		}
	}
	panic(fmt.Sprintf("GetPointByNR failed for nr:%d", nr))
}

func GetSyscallPointByName(name string) *SyscallPoint {
	return aarch64_syscall_points.GetPointByName(name)
}

func GetSyscallPointByNR(nr uint32) *SyscallPoint {
	return aarch64_syscall_points.GetPointByNR(nr)
}

var aarch64_syscall_points = SyscallPoints{}

func R(nr uint32, name string, point_args ...*PointArg) {
	if aarch64_syscall_points.Dup(nr, name) {
		panic(fmt.Sprintf("register duplicate for nr:%d name:%s", nr, name))
	}
	var a_point_args []*PointArg
	var b_point_args []*PointArg
	for reg_index, point_arg := range point_args {
		a_p := point_arg.Clone()
		a_p.SetRegIndex(uint32(reg_index))
		a_p.BuildOpList(point_arg.PointType == EBPF_SYS_ENTER || point_arg.PointType == EBPF_SYS_ALL)
		a_point_args = append(a_point_args, a_p)
		b_p := point_arg.Clone()
		b_p.SetRegIndex(uint32(reg_index))
		b_p.BuildOpList(point_arg.PointType == EBPF_SYS_EXIT || point_arg.PointType == EBPF_SYS_ALL)
		b_point_args = append(b_point_args, b_p)
	}
	// SetRegIndex + BuildOpList 读取寄存器才会产生
	// 直接添加 ARG_INT 刚好不影响读取数据 并且能正常进行解析
	b_point_args = append(b_point_args, B("ret", GetArgType("int")))
	point := &SyscallPoint{nr, name, a_point_args, b_point_args}
	aarch64_syscall_points.Add(point)
}

func A(arg_name string, arg_type IArgType) *PointArg {
	return NewPointArg(arg_name, arg_type, EBPF_SYS_ENTER)
}

func B(arg_name string, arg_type IArgType) *PointArg {
	return NewPointArg(arg_name, arg_type, EBPF_SYS_EXIT)
}

func C(arg_name string, arg_type IArgType) *PointArg {
	return NewPointArg(arg_name, arg_type, EBPF_SYS_ALL)
}

func init() {
	var POINTER = GetArgType("ptr")
	var INT = GetArgType("int")
	var UINT = GetArgType("uint")
	var INT16 = GetArgType("int16")
	var UINT64 = GetArgType("uint64")
	var STRING = GetArgType("string")
	var BUFFER = GetArgType("buffer")
	var IOVEC = GetArgType("iovec")
	var MSGHDR = GetArgType("msghdr")
	var SOCKLEN_T = GetArgType("socklen_t")
	var SIZE_T = GetArgType("size_t")
	// var SSIZE_T = GetArgType("ssize_t")
	var SOCKADDR = GetArgType("sockaddr")
	var TIMESPEC = GetArgType("timespec")
	var STAT = GetArgType("stat")
	var POLLFD = GetArgType("pollfd")
	var SIGACTION = GetArgType("sigaction")
	var SIGINFO = GetArgType("siginfo")
	var STACK_T = GetArgType("stack_t")
	var LINUX_DIRENT64 = GetArgType("dirent")
	// 对一些复杂结构体的读取配置进行补充
	STRING_ARRAY := GetStrArr()
	ITTMERSPEC := GetItTmerspec()
	RUSAGE := GetRusage()
	UTSNAME := GetUtsname()
	TIMEVAL := GetTimeval()
	TIMEZONE := GetTimeZone()
	SYSINFO := GetSysinfo()
	STATFS := GetStatfs()
	EPOLLEVENT := GetEpollEvent()
	INT_ARRAY_2 := ReadAsArray(INT, 2)
	// #define SI_MAX_SIZE 128
	// int _si_pad[SI_MAX_SIZE / sizeof(int)];
	// 实测基本上就只有第一个是有效的信号
	// SIGINFO_V2 := ReadAsArray(INT, 32)
	SIGINFO_V2 := ReadAsArray(INT, 1)
	// 64 位下这个是 unsigned long sig[_NSIG_WORDS]
	// #define _NSIG       64
	// #define _NSIG_BPW   __BITS_PER_LONG -> 64 或者 32
	// #define _NSIG_WORDS (_NSIG / _NSIG_BPW)
	// unsigned long -> 4
	UINT_ARRAY_1 := ReadAsArray(NewNumFormat(UINT, FORMAT_HEX), 1)
	SIGSET_PTR := SetupPtrType(UINT_ARRAY_1, false)
	INT_PTR := SetupPtrType(INT, true)
	UINT_PTR := SetupPtrType(UINT, true)

	BUFFER_X2 := RegAsBufferReadLen(BUFFER, REG_ARM64_X2)
	IOVEC_X2 := RegAsIovecLoopCount(IOVEC, REG_ARM64_X2)

	INT_SOCKET_FLAGS := AttachFlagsParser(INT, SocketFlagsParser)
	INT_FILE_FLAGS := AttachFlagsParser(INT, FileFlagsParser)
	INT16_PERM_FLAGS := AttachFlagsParser(INT16, PermissionFlagsParser)

	// MSGHDR.DumpOpList()

	R(0, "io_setup", A("nr_events", UINT), A("ctx_idp", POINTER))
	R(1, "io_destroy", A("ctx", POINTER))
	R(2, "io_submit", A("ctx_id", POINTER), A("nr", UINT64), A("iocbpp", POINTER))
	R(3, "io_cancel", A("ctx_id", POINTER), A("iocb", POINTER), A("result", POINTER))
	R(4, "io_getevents", A("ctx_id", POINTER), A("min_nr", UINT64), A("nr", UINT64), A("events", POINTER), A("timeout", TIMESPEC))
	R(5, "setxattr", A("pathname", STRING), A("name", STRING), A("value", POINTER), A("size", INT), A("flags", INT))
	R(6, "lsetxattr", A("pathname", STRING), A("name", STRING), A("value", POINTER), A("size", INT), A("flags", INT))
	R(7, "fsetxattr", A("fd", INT), A("name", STRING), A("value", POINTER), A("size", INT), A("flags", INT))
	R(8, "getxattr", A("path", STRING), A("name", STRING), A("value", POINTER), A("size", INT))
	R(9, "lgetxattr", A("path", STRING), A("name", STRING), A("value", POINTER), A("size", INT))
	R(10, "fgetxattr", A("fd", INT), A("name", STRING), A("value", POINTER), A("size", INT))
	R(11, "listxattr", A("pathname", STRING), A("list", STRING), A("size", INT))
	R(12, "llistxattr", A("pathname", STRING), A("list", STRING), A("size", INT))
	R(13, "flistxattr", A("fd", INT), A("list", STRING), A("size", INT))
	R(14, "removexattr", A("pathname", STRING), A("name", STRING))
	R(15, "lremovexattr", A("pathname", STRING), A("name", STRING))
	R(16, "fremovexattr", A("fd", INT), A("name", STRING))
	R(17, "getcwd", B("buf", STRING), A("size", UINT64))
	R(18, "lookup_dcookie", A("cookie", INT), B("buffer", STRING), A("len", INT))
	R(19, "eventfd2", A("initval", INT), A("flags", INT))
	R(20, "epoll_create1", A("flags", INT))
	R(21, "epoll_ctl", A("epfd", INT), A("op", INT), A("fd", INT), A("event", EPOLLEVENT))
	R(22, "epoll_pwait", A("epfd", INT), A("events", POINTER), A("maxevents", INT), A("timeout", INT), A("sigmask", SIGSET_PTR), A("sigsetsize", INT))
	R(23, "dup", A("oldfd", INT))
	R(24, "dup3", A("oldfd", INT), A("newfd", INT), A("flags", INT))
	R(25, "fcntl", A("fd", INT), A("cmd", INT), A("arg", INT))
	R(26, "inotify_init1", A("flags", INT))
	R(27, "inotify_add_watch", A("fd", INT), A("pathname", STRING), A("mask", INT))
	R(28, "inotify_rm_watch", A("fd", INT), A("wd", INT))
	R(29, "ioctl", A("fd", INT), A("request", UINT64), A("arg0", INT), A("arg1", INT), A("arg2", INT), A("arg3", INT))
	R(30, "ioprio_set", A("which", INT), A("who", INT), A("ioprio", INT))
	R(31, "ioprio_get", A("which", INT), A("who", INT))
	R(32, "flock", A("fd", INT), A("operation", INT))
	R(33, "mknodat", A("dfd", INT), A("filename", STRING), A("mode", INT16_PERM_FLAGS), A("dev", INT))
	R(34, "mkdirat", A("dirfd", INT), A("pathname", STRING), A("mode", INT16_PERM_FLAGS))
	R(35, "unlinkat", A("dirfd", INT), A("pathname", STRING), A("flags", INT))
	R(36, "symlinkat", A("target", STRING), A("newdirfd", INT), A("linkpath", STRING))
	R(37, "linkat", A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING), A("flags", INT))
	R(38, "renameat", A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING))
	R(39, "umount2", A("target", STRING), A("flags", INT))
	R(40, "mount", A("source", INT), A("target", STRING), A("filesystemtype", STRING), A("mountflags", INT), A("data", POINTER))
	R(41, "pivot_root", A("new_root", STRING), A("put_old", STRING))
	R(42, "nfsservctl", A("cmd", INT), A("argp", POINTER), A("resp", POINTER))
	R(43, "statfs", A("path", STRING), B("buf", STATFS))
	R(44, "fstatfs", A("fd", INT), B("buf", STATFS))
	R(45, "truncate", A("path", STRING), A("length", INT))
	R(46, "ftruncate", A("fd", INT), A("length", INT))
	R(47, "fallocate", A("fd", INT), A("mode", INT), A("offset", INT), A("len", INT))
	R(48, "faccessat", A("dirfd", INT), A("pathname", STRING), A("flags", INT), A("mode", INT))
	R(49, "chdir", A("path", STRING))
	R(50, "fchdir", A("fd", INT))
	R(51, "chroot", A("path", STRING))
	R(52, "fchmod", A("fd", INT), A("mode", INT16_PERM_FLAGS))
	R(53, "fchmodat", A("dirfd", INT), A("pathname", STRING), A("mode", INT16_PERM_FLAGS), A("flags", INT))
	R(54, "fchownat", A("dirfd", INT), A("pathname", STRING), A("owner", INT), A("group", INT), A("flags", INT))
	R(55, "fchown", A("fd", INT), A("owner", INT), A("group", INT))
	R(56, "openat", A("dirfd", INT), A("*pathname", STRING), A("flags", INT_FILE_FLAGS), A("mode", INT16_PERM_FLAGS))
	R(57, "close", A("fd", INT))
	R(58, "vhangup")
	R(59, "pipe2", B("pipefd", INT_ARRAY_2), A("flags", INT))
	R(60, "quotactl", A("cmd", INT), A("special", STRING), A("id", INT), A("addr", INT))
	R(61, "getdents64", A("fd", INT), B("dirp", LINUX_DIRENT64), A("count", INT))
	R(62, "lseek", A("fd", INT), A("offset", INT), A("whence", INT))
	R(63, "read", A("fd", INT), B("buf", BUFFER_X2), A("count", INT))
	R(64, "write", A("fd", INT), A("buf", BUFFER_X2), A("count", INT))
	R(65, "readv", A("fd", INT), B("iov", IOVEC_X2), A("iovcnt", INT))
	R(66, "writev", A("fd", INT), A("*iov", IOVEC_X2), A("iovcnt", INT))
	R(67, "pread64", A("fd", INT), B("buf", BUFFER_X2), A("count", INT), A("offset", INT))
	R(68, "pwrite64", A("fd", INT), A("buf", BUFFER_X2), A("count", INT), A("offset", INT))
	R(69, "preadv", A("fd", INT), B("iov", IOVEC_X2), A("iovcnt", INT), A("offset", INT))
	R(70, "pwritev", A("fd", INT), A("iov", IOVEC_X2), A("iovcnt", INT), A("offset", INT))
	R(71, "sendfile", A("out_fd", INT), A("in_fd", INT), A("offset", INT), A("count", INT))
	R(72, "pselect6", A("n", INT), A("inp", POINTER), A("outp", POINTER), A("exp", POINTER), A("tsp", TIMESPEC), A("sig", POINTER))
	R(73, "ppoll", A("fds", POLLFD), A("nfds", INT), A("tmo_p", TIMESPEC), A("sigmask", SIGSET_PTR), A("sigsetsize", INT))
	R(74, "signalfd4", A("ufd", INT), A("user_mask", POINTER), A("sizemask", INT), A("flags", INT))
	R(75, "vmsplice", A("fd", INT), A("uiov", IOVEC_X2), A("nr_segs", INT), A("flags", INT))
	R(76, "splice", A("fd_in", INT), A("off_in", INT), A("fd_out", INT), A("off_out", INT), A("len", INT), A("flags", INT))
	R(77, "tee", A("fdin", INT), A("fdout", INT), A("len", INT), A("flags", INT))
	R(78, "readlinkat", A("dirfd", INT), A("pathname", STRING), B("buf", STRING), A("bufsiz", INT))
	R(79, "newfstatat", A("dirfd", INT), A("pathname", STRING), B("statbuf", STAT), A("flags", INT))
	R(80, "fstat", A("fd", INT), B("statbuf", STAT))
	R(81, "sync")
	R(82, "fsync", A("fd", INT))
	R(83, "fdatasync", A("fd", INT))
	R(84, "sync_file_range", A("fd", INT), A("offset", INT), A("nbytes", INT), A("flags", INT))
	R(85, "timerfd_create", A("clockid", INT), A("flags", INT))
	R(86, "timerfd_settime", A("fd", INT), A("flags", INT), A("new_value", ITTMERSPEC), A("old_value", ITTMERSPEC))
	R(87, "timerfd_gettime", A("fd", INT), B("curr_value", ITTMERSPEC))
	R(88, "utimensat", A("dirfd", INT), A("pathname", STRING), A("times", ITTMERSPEC), A("flags", INT))
	R(89, "acct", A("name", STRING))
	R(90, "capget", A("header", POINTER), A("dataptr", POINTER))
	R(91, "capset", A("header", POINTER), A("data", POINTER))
	R(92, "personality", A("personality", INT))
	R(93, "exit", A("status", INT))
	R(94, "exit_group", A("status", INT))
	R(95, "waitid", A("which", INT), A("upid", INT), A("infop", SIGINFO), A("options", INT), A("ru", RUSAGE))
	R(96, "set_tid_address", A("tidptr", POINTER))
	R(97, "unshare", A("unshare_flags", INT))
	R(98, "futex", A("uaddr", UINT_PTR), A("op", INT), A("val", INT), C("timeout", TIMESPEC), A("uaddr2", UINT_PTR), A("val3", UINT))
	R(99, "set_robust_list", A("head", POINTER), A("len", INT))
	R(100, "get_robust_list", A("pid", INT), A("head_ptr", POINTER), A("len_ptr", INT))
	R(101, "nanosleep", A("req", TIMESPEC), A("rem", TIMESPEC))
	R(102, "getitimer", A("which", INT), A("value", POINTER))
	R(103, "setitimer", A("which", INT), A("value", POINTER), A("ovalue", POINTER))
	R(104, "kexec_load", A("entry", INT), A("nr_segments", INT), A("segments", POINTER), A("flags", INT))
	R(105, "init_module", A("umod", POINTER), A("len", INT), A("uargs", STRING))
	R(106, "delete_module", A("name_user", STRING), A("flags", INT))
	R(107, "timer_create", A("which_clock", INT), A("timer_event_spec", POINTER), A("created_timer_id", INT))
	R(108, "timer_gettime", A("timer_id", INT), A("setting", POINTER))
	R(109, "timer_getoverrun", A("timer_id", INT))
	R(110, "timer_settime", A("timer_id", INT), A("flags", INT), A("new_setting", POINTER), A("old_setting", POINTER))
	R(111, "timer_delete", A("timer_id", INT))
	R(112, "clock_settime", A("clockid", INT), A("tp", TIMESPEC))
	R(113, "clock_gettime", A("clockid", INT), B("tp", TIMESPEC))
	R(114, "clock_getres", A("clockid", INT), B("res", TIMESPEC))
	R(115, "clock_nanosleep", A("clockid", INT), A("flags", INT), A("request", TIMESPEC), B("remain", TIMESPEC))
	R(116, "syslog", A("type", INT), A("bufp", STRING), A("len", INT))
	R(117, "ptrace", A("request", INT), A("pid", INT), A("addr", POINTER), A("data", POINTER))
	R(118, "sched_setparam", A("pid", INT), A("param", INT_PTR))
	R(119, "sched_setscheduler", A("pid", INT), A("policy", INT), B("param", INT_PTR))
	R(120, "sched_getscheduler", A("pid", INT))
	R(121, "sched_getparam", A("pid", INT), B("param", POINTER))
	R(122, "sched_setaffinity", A("pid", INT), A("cpusetsize", INT), A("mask", UINT_PTR))
	R(123, "sched_getaffinity", A("pid", INT), A("cpusetsize", INT), B("mask", UINT_PTR))
	R(124, "sched_yield")
	R(125, "sched_get_priority_max", A("policy", INT))
	R(126, "sched_get_priority_min", A("policy", INT))
	R(127, "sched_rr_get_interval", A("pid", INT), A("interval", TIMESPEC))
	R(128, "restart_syscall")
	R(129, "kill", A("pid", INT), A("sig", INT))
	R(130, "tkill", A("tid", INT), A("sig", INT))
	R(131, "tgkill", A("tgid", INT), A("tid", INT), A("sig", INT))
	R(132, "sigaltstack", A("ss", STACK_T), A("old_ss", STACK_T))
	R(133, "rt_sigsuspend", A("mask", SIGSET_PTR))
	R(134, "rt_sigaction", A("signum", INT), A("act", SIGACTION), A("oldact", SIGACTION))
	R(135, "rt_sigprocmask", A("how", INT), A("set", SIGSET_PTR), A("oldset", SIGSET_PTR), A("sigsetsize", SIZE_T))
	R(136, "rt_sigpending", A("uset", SIGSET_PTR), A("sigsetsize", INT))
	R(137, "rt_sigtimedwait", A("uthese", SIGSET_PTR), A("uinfo", SIGINFO), A("uts", TIMESPEC), A("sigsetsize", SIZE_T))
	R(138, "rt_sigqueueinfo", A("pid", INT), A("sig", INT), A("uinfo", SIGINFO))
	R(139, "rt_sigreturn", A("mask", INT))
	R(140, "setpriority", A("which", INT), A("who", INT), A("prio", INT))
	R(141, "getpriority", A("which", INT), A("who", INT))
	R(142, "reboot", A("magic1", INT), A("magic2", INT), A("cmd", INT), A("arg", POINTER))
	R(143, "setregid", A("rgid", INT), A("egid", INT))
	R(144, "setgid", A("gid", INT))
	R(145, "setreuid", A("ruid", INT), A("euid", INT))
	R(146, "setuid", A("uid", INT))
	R(147, "setresuid", A("ruid", INT), A("euid", INT), A("suid", INT))
	R(148, "getresuid", A("ruidp", INT), A("euidp", INT), A("suidp", INT))
	R(149, "setresgid", A("rgid", INT), A("egid", INT), A("sgid", INT))
	R(150, "getresgid", A("rgidp", INT), A("egidp", INT), A("sgidp", INT))
	R(151, "setfsuid", A("uid", INT))
	R(152, "setfsgid", A("gid", INT))
	R(153, "times", A("tbuf", POINTER))
	R(154, "setpgid", A("pid", INT), A("pgid", INT))
	R(155, "getpgid", A("pid", INT))
	R(156, "getsid", A("pid", INT))
	R(157, "setsid")
	R(158, "getgroups", A("gidsetsize", INT), A("grouplist", INT))
	R(159, "setgroups", A("gidsetsize", INT), A("grouplist", INT))
	R(160, "uname", B("buf", UTSNAME))
	R(161, "sethostname", A("name", STRING), A("len", INT))
	R(162, "setdomainname", A("name", STRING), A("len", INT))
	R(163, "getrlimit", A("resource", INT), B("rlim", POINTER))
	R(164, "setrlimit", A("resource", UTSNAME), A("rlim", POINTER))
	R(165, "getrusage", A("who", INT), B("usage", RUSAGE))
	R(166, "umask", A("mode", INT))
	R(167, "prctl", A("option", INT), A("arg2", UINT64), A("arg3", UINT64), A("arg4", UINT64), A("arg5", UINT64))
	R(168, "getcpu", A("cpup", INT), A("nodep", INT), A("unused", POINTER))
	R(169, "gettimeofday", B("tv", TIMEVAL), B("tz", TIMEZONE))
	R(170, "settimeofday", A("tv", TIMEVAL), A("tz", TIMEZONE))
	R(171, "adjtimex", A("txc_p", POINTER))
	R(172, "getpid")
	R(173, "getppid")
	R(174, "getuid")
	R(175, "geteuid")
	R(176, "getgid")
	R(177, "getegid")
	R(178, "gettid")
	R(179, "sysinfo", B("info", SYSINFO))
	R(180, "mq_open", A("u_name", STRING), A("oflag", INT), A("mode", INT16_PERM_FLAGS), A("u_attr", POINTER))
	R(181, "mq_unlink", A("u_name", STRING))
	R(182, "mq_timedsend", A("mqdes", INT), A("u_msg_ptr", STRING), A("msg_len", INT), A("msg_prio", INT), A("u_abs_timeout", TIMESPEC))
	R(183, "mq_timedreceive", A("mqdes", INT), A("u_msg_ptr", STRING), A("msg_len", INT), A("u_msg_prio", INT), A("u_abs_timeout", TIMESPEC))
	R(184, "mq_notify", A("mqdes", INT), A("u_notification", POINTER))
	R(185, "mq_getsetattr", A("mqdes", INT), A("u_mqstat", POINTER), A("u_omqstat", POINTER))
	R(186, "msgget", A("key", INT), A("msgflg", INT))
	R(187, "msgctl", A("msqid", INT), A("cmd", INT), A("buf", POINTER))
	R(188, "msgrcv", A("msqid", INT), A("msgp", POINTER), A("msgsz", INT), A("msgtyp", UINT64), A("msgflg", INT))
	R(189, "msgsnd", A("msqid", INT), A("msgp", POINTER), A("msgsz", INT), A("msgflg", INT))
	R(190, "semget", A("key", INT), A("nsems", INT), A("semflg", INT))
	R(191, "semctl", A("semid", INT), A("semnum", INT), A("cmd", INT), A("arg", INT))
	R(192, "semtimedop", A("semid", INT), A("tsops", POINTER), A("nsops", INT), A("timeout", TIMESPEC))
	R(193, "semop", A("semid", INT), A("tsops", POINTER), A("nsops", INT))
	R(194, "shmget", A("key", INT), A("size", INT), A("shmflg", INT))
	R(195, "shmctl", A("shmid", INT), A("cmd", INT), A("buf", POINTER))
	R(196, "shmat", A("shmid", INT), A("shmaddr", POINTER), A("shmflg", INT))
	R(197, "shmdt", A("shmaddr", POINTER))
	R(198, "socket", A("domain", INT), A("type", INT_SOCKET_FLAGS), A("protocol", INT))
	R(199, "socketpair", A("domain", INT), A("type", INT), A("protocol", INT), B("sv", INT_ARRAY_2))
	R(200, "bind", A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(201, "listen", A("sockfd", INT), A("backlog", INT))
	R(202, "accept", A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(203, "connect", A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(204, "getsockname", A("sockfd", INT), B("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(205, "getpeername", A("sockfd", INT), B("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(206, "sendto", A("sockfd", INT), A("*buf", BUFFER_X2), A("len", SIZE_T), A("flags", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(207, "recvfrom", A("sockfd", INT), B("*buf", BUFFER_X2), A("len", SIZE_T), A("flags", INT))
	R(208, "setsockopt", A("sockfd", INT), A("level", INT), A("optname", INT), A("optval", POINTER), A("optlen", SOCKLEN_T))
	R(209, "getsockopt", A("sockfd", INT), A("level", INT), A("optname", INT), B("optval", POINTER), A("optlen", POINTER))
	R(210, "shutdown", A("sockfd", INT), A("how", INT))
	R(211, "sendmsg", A("sockfd", INT), A("*msg", MSGHDR), A("flags", INT))
	R(212, "recvmsg", A("sockfd", INT), B("*msg", MSGHDR), A("flags", INT))
	R(213, "readahead", A("fd", INT), A("offset", INT), A("count", INT))
	R(214, "brk", A("brk", INT))
	R(215, "munmap", A("addr", UINT64), A("length", INT))
	R(216, "mremap", A("old_address", POINTER), A("old_size", INT), A("new_size", INT), A("flags", INT))
	R(217, "add_key", A("_type", STRING), A("_description", STRING), A("_payload", POINTER), A("plen", INT), A("ringid", INT))
	R(218, "request_key", A("_type", STRING), A("_description", STRING), A("_callout_info", STRING), A("destringid", INT))
	R(219, "keyctl", A("option", INT), A("arg2", INT), A("arg3", INT), A("arg4", INT), A("arg5", INT))
	R(220, "clone", A("fn", POINTER), A("stack", POINTER), A("flags", INT), A("arg0", INT), A("arg1", INT), A("arg2", INT))
	R(221, "execve", A("pathname", STRING), A("argv", STRING_ARRAY), A("envp", STRING_ARRAY))
	R(222, "mmap", B("addr", POINTER), A("length", INT), A("prot", INT), A("flags", INT), A("fd", INT), A("offset", INT))
	R(223, "fadvise64", A("fd", INT), A("offset", INT), A("len", INT), A("advice", INT))
	R(224, "swapon", A("specialfile", STRING), A("swap_flags", INT))
	R(225, "swapoff", A("specialfile", STRING))
	R(226, "mprotect", A("addr", POINTER), A("length", INT), A("prot", INT))
	R(227, "msync", A("addr", POINTER), A("length", INT), A("flags", INT))
	R(228, "mlock", A("start", INT), A("len", INT))
	R(229, "munlock", A("start", INT), A("len", INT))
	R(230, "mlockall", A("flags", INT))
	R(231, "munlockall")
	R(232, "mincore", A("start", INT), A("len", INT), A("vec", STRING))
	R(233, "madvise", A("addr", POINTER), A("len", INT), A("advice", INT))
	R(234, "remap_file_pages", A("start", INT), A("size", INT), A("prot", INT), A("pgoff", INT), A("flags", INT))
	R(235, "mbind", A("start", INT), A("len", INT), A("mode", INT), A("nmask", INT), A("maxnode", INT), A("flags", INT))
	R(236, "get_mempolicy", A("policy", INT), A("nmask", INT), A("maxnode", INT), A("addr", INT), A("flags", INT))
	R(237, "set_mempolicy", A("mode", INT), A("nmask", INT), A("maxnode", INT))
	R(238, "migrate_pages", A("pid", INT), A("maxnode", INT), A("old_nodes", INT), A("new_nodes", INT))
	R(239, "move_pages", A("pid", INT), A("nr_pages", INT), A("pages", POINTER), A("nodes", INT), A("status", INT), A("flags", INT))
	R(240, "rt_tgsigqueueinfo", A("tgid", INT), A("tid", INT), A("sig", INT), A("siginfo", SIGINFO_V2))
	R(241, "perf_event_open", A("attr_uptr", POINTER), A("pid", INT), A("cpu", INT), A("group_fd", INT), A("flags", INT))
	R(242, "accept4", A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", INT), A("flags", INT))
	R(243, "recvmmsg", A("fd", INT), B("mmsg", MSGHDR), A("vlen", INT), A("flags", INT), A("timeout", TIMESPEC))
	R(260, "wait4", A("pid", INT), A("wstatus", POINTER), A("options", INT), B("rusage", RUSAGE))
	R(261, "prlimit64", A("pid", INT), A("resource", INT), A("new_rlim", POINTER), A("old_rlim", POINTER))
	R(262, "fanotify_init", A("flags", INT), A("event_f_flags", INT))
	R(263, "fanotify_mark", A("fanotify_fd", INT), A("flags", INT), A("mask", UINT64), A("dfd", INT), A("pathname", STRING))
	R(264, "name_to_handle_at", A("dfd", INT), A("name", STRING), A("handle", POINTER), A("mnt_id", INT), A("flag", INT))
	R(265, "open_by_handle_at", A("mountdirfd", INT), A("handle", POINTER), A("flags", INT))
	R(266, "clock_adjtime", A("which_clock", INT), A("utx", POINTER))
	R(267, "syncfs", A("fd", INT))
	R(268, "setns", A("fd", INT), A("flags", INT))
	R(269, "sendmmsg", A("fd", INT), A("mmsg", MSGHDR), A("vlen", INT), A("flags", INT))
	// 虽然处于内核 但是实测无法跨进程读取数据 所以对于这两个系统调用 只能获取 local_iov 的内容
	R(270, "process_vm_readv", A("pid", INT), B("local_iov", IOVEC_X2), A("liovcnt", INT), A("remote_iov", POINTER), A("riovcnt", INT), A("flags", INT))
	R(271, "process_vm_writev", A("pid", INT), A("local_iov", IOVEC_X2), A("liovcnt", INT), B("remote_iov", POINTER), A("riovcnt", INT), A("flags", INT))
	R(272, "kcmp", A("pid1", INT), A("pid2", INT), A("type", INT), A("idx1", INT), A("idx2", INT))
	R(273, "finit_module", A("fd", INT), A("uargs", STRING), A("flags", INT))
	R(274, "sched_setattr", A("pid", INT), A("uattr", POINTER), A("flags", INT))
	R(275, "sched_getattr", A("pid", INT), A("uattr", POINTER), A("usize", INT), A("flags", INT))
	R(276, "renameat2", A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING), A("flags", INT))
	R(277, "seccomp", A("operation", INT), A("flags", INT), A("args", POINTER))
	R(278, "getrandom", B("buf", POINTER), A("buflen", INT), A("flags", INT))
	R(279, "memfd_create", A("name", STRING), A("flags", INT))
	R(280, "bpf", A("cmd", INT), A("attr", POINTER), A("size", INT))
	R(281, "execveat", A("dirfd", INT), A("pathname", STRING), A("argv", STRING_ARRAY), A("envp", STRING_ARRAY), A("flags", INT))
	R(282, "userfaultfd", A("flags", INT))
	R(283, "membarrier", A("cmd", INT), A("flags", POINTER), A("cpu_id", INT))
	R(284, "mlock2", A("start", INT), A("len", INT), A("flags", INT))
	R(285, "copy_file_range", A("fd_in", INT), A("off_in", INT), A("fd_out", INT), A("off_out", INT), A("len", INT), A("flags", INT))
	R(286, "preadv2", A("fd", INT), A("vec", POINTER), A("vlen", INT), A("pos_l", INT), A("pos_h", INT), A("flags", INT))
	R(287, "pwritev2", A("fd", INT), A("vec", POINTER), A("vlen", INT), A("pos_l", INT), A("pos_h", INT), A("flags", INT))
	R(288, "pkey_mprotect", B("addr", POINTER), A("length", INT), A("prot", INT), A("pkey", INT))
	R(289, "pkey_alloc", A("flags", INT), A("init_val", INT))
	R(290, "pkey_free", A("pkey", INT))
	R(291, "statx", A("dfd", INT), A("filename", STRING), A("flags", INT), A("mask", INT), A("buffer", POINTER))
	R(292, "io_pgetevents", A("ctx_id", POINTER), A("min_nr", UINT64), A("nr", UINT64), A("events", POINTER), A("timeout", TIMESPEC), A("usig", POINTER))
	R(293, "rseq", A("rseq", POINTER), A("rseq_len", INT), A("flags", INT), A("sig", INT))
	R(294, "kexec_file_load", A("kernel_fd", INT), A("initrd_fd", INT), A("cmdline_len", INT), A("cmdline_ptr", STRING), A("flags", INT))
	R(424, "pidfd_send_signal", A("pidfd", INT), A("sig", INT), A("info", SIGINFO), A("flags", INT))
	R(425, "io_uring_setup", A("entries", INT), A("params", POINTER))
	R(426, "io_uring_enter", A("fd", INT), A("to_submit", INT), A("min_complete", INT), A("flags", INT), A("argp", POINTER), A("argsz", INT))
	R(427, "io_uring_register", A("fd", INT), A("opcode", INT), A("arg", POINTER), A("nr_args", INT))
	R(428, "open_tree", A("dfd", INT), A("filename", STRING), A("flags", INT))
	R(429, "move_mount", A("from_dfd", INT), A("from_pathname", STRING), A("to_dfd", INT), A("to_pathname", STRING), A("flags", INT))
	R(430, "fsopen", A("_fs_name", STRING), A("flags", INT))
	R(431, "fsconfig", A("fd", INT), A("cmd", INT), A("_key", STRING), A("_value", POINTER), A("aux", INT))
	R(432, "fsmount", A("fs_fd", INT), A("flags", INT), A("attr_flags", INT))
	R(433, "fspick", A("dfd", INT), A("path", STRING), A("flags", INT))
	R(434, "pidfd_open", A("pid", INT), A("flags", INT))
	R(435, "clone3", A("uargs", POINTER), A("size", INT))
	R(436, "close_range", A("fd", INT), A("max_fd", INT), A("flags", INT))
	R(437, "openat2", A("dfd", INT), A("filename", STRING), A("how", POINTER), A("usize", INT))
	R(438, "pidfd_getfd", A("pidfd", INT), A("fd", INT), A("flags", INT))
	R(439, "faccessat2", A("dirfd", INT), A("pathname", STRING), A("flags", INT), A("mode", INT))
	R(440, "process_madvise", A("pidfd", INT), A("vec", POINTER), A("vlen", INT), A("behavior", INT), A("flags", INT))
	R(441, "epoll_pwait2", A("epfd", INT), A("events", POINTER), A("maxevents", INT), A("timeout", TIMESPEC), A("sigmask", SIGSET_PTR), A("sigsetsize", INT))
	R(442, "mount_setattr", A("dfd", INT), A("path", STRING), A("flags", INT), A("uattr", POINTER), A("usize", INT))
	R(443, "quotactl_fd", A("fd", INT), A("cmd", INT), A("id", INT), A("addr", POINTER))
	R(444, "landlock_create_ruleset", A("attr", POINTER), A("size", INT), A("flags", INT))
	R(445, "landlock_add_rule", A("ruleset_fd", INT), A("rule_type", INT), A("rule_attr", POINTER), A("flags", INT))
	R(446, "landlock_restrict_self", A("ruleset_fd", INT), A("flags", INT))
	R(447, "memfd_secret", A("flags", INT))
	R(448, "process_mrelease", A("pidfd", INT), A("flags", INT))
	R(449, "futex_waitv", A("waiters", POINTER), A("nr_futexes", INT), A("flags", INT), A("timeout", TIMESPEC), A("clockid", INT))
	R(450, "set_mempolicy_home_node", A("start", INT), A("len", INT), A("home_node", INT), A("flags", INT))
}
