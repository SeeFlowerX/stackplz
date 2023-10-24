package config

import (
	"encoding/binary"
	"strings"
	"syscall"
	"unsafe"
)

type SysCallArgs struct {
	NR uint32
	PointArgs
}

type SArgs = SysCallArgs

type SyscallPointArgs_T struct {
	NR         uint32
	Count      uint32
	ArgTypes   [MAX_POINT_ARG_COUNT]FilterArgType
	ArgTypeRet FilterArgType
}

func (this *SysCallArgs) ParseFlag(value int32) string {
	// 借助这个函数对 flags 进行解析 增强可读性
	var ops []FlagOp
	switch this.PointArgs.PointName {
	case "openat":
		ops = FileFlags
	case "mmap":
		ops = MapFlags
	case "mremap":
		ops = MreapFlags
	default:
		return ""
	}
	return this.ParseOp(value, &ops)
}

func (this *SysCallArgs) ParseType(value int32) string {
	var ops []FlagOp
	switch this.PointArgs.PointName {
	case "socket", "socketpair":
		ops = SocketTypes
	default:
		return ""
	}
	return this.ParseOp(value, &ops)
}

func (this *SysCallArgs) ParseProt(value int32) string {
	var ops []FlagOp
	switch this.PointArgs.PointName {
	case "mmap":
		ops = ProtFlags
	default:
		return ""
	}
	return this.ParseOp(value, &ops)
}

func (this *SysCallArgs) ParseMode(value int32) string {
	var ops []FlagOp
	switch this.PointArgs.PointName {
	case "openat":
		ops = PermissionFlags
	default:
		return ""
	}
	return this.ParseOp(value, &ops)
}

func (this *SysCallArgs) ParseOp(value int32, ops *[]FlagOp) string {
	var info []string
	for _, op := range *ops {
		if value&op.Value == op.Value {
			info = append(info, op.Name)
		}
	}
	if len(info) > 0 {
		return "(" + strings.Join(info, "|") + ")"
	} else {
		return ""
	}
}

func (this *SysCallArgs) GetConfig() *SyscallPointArgs_T {
	var point_arg_types [MAX_POINT_ARG_COUNT]FilterArgType
	for i := 0; i < MAX_POINT_ARG_COUNT; i++ {
		if i+1 > len(this.Args) {
			for j := 0; j < MAX_FILTER_COUNT; j++ {
				point_arg_types[i].ArgType.FilterIdx[j] = FILTER_INDEX_NONE
			}
		} else {
			point_arg_types[i].PointFlag = this.Args[i].PointFlag
			point_arg_types[i].ArgType = this.Args[i].ArgType
		}
	}
	var point_arg_type_ret FilterArgType
	point_arg_type_ret.PointFlag = this.Ret.PointFlag
	point_arg_type_ret.ArgType = this.Ret.ArgType
	config := &SyscallPointArgs_T{
		NR:         this.NR,
		Count:      uint32(len(this.Args)),
		ArgTypes:   point_arg_types,
		ArgTypeRet: point_arg_type_ret,
	}
	return config
}

const (
	TYPE_NONE uint32 = iota
	TYPE_NUM
	TYPE_EXP_INT
	TYPE_INT
	TYPE_UINT
	TYPE_INT16
	TYPE_UINT16
	TYPE_INT32
	TYPE_UINT32
	TYPE_INT64
	TYPE_UINT64
	TYPE_STRING
	TYPE_STRING_ARR
	TYPE_POINTER
	TYPE_STRUCT
	TYPE_TIMESPEC
	TYPE_STAT
	TYPE_STATFS
	TYPE_SIGACTION
	TYPE_UTSNAME
	TYPE_SOCKADDR
	TYPE_RUSAGE
	TYPE_IOVEC
	TYPE_EPOLLEVENT
	TYPE_SIGSET
	TYPE_POLLFD
	TYPE_SYSINFO
	TYPE_SIGINFO
	TYPE_MSGHDR
	TYPE_ITIMERSPEC
	TYPE_STACK_T
	TYPE_TIMEVAL
	TYPE_TIMEZONE
	TYPE_PTHREAD_ATTR
	TYPE_ARRAY
	TYPE_ARRAY_INT32
	TYPE_ARRAY_UINT32
	TYPE_BUFFER
)

func A(arg_name string, arg_type ArgType) PArg {
	return PArg{arg_name, SYS_ENTER, arg_type, "???"}
}

func B(arg_name string, arg_type ArgType) PArg {
	return PArg{arg_name, SYS_EXIT, arg_type, "???"}
}

var NONE = AT(TYPE_NONE, TYPE_NONE, 0)

var EXP_INT = AT(TYPE_EXP_INT, TYPE_NUM, uint32(unsafe.Sizeof(int32(0))))
var INT = AT(TYPE_INT, TYPE_NUM, uint32(unsafe.Sizeof(int(0))))
var UINT = AT(TYPE_UINT, TYPE_NUM, uint32(unsafe.Sizeof(uint(0))))
var INT16 = AT(TYPE_INT16, TYPE_NUM, uint32(unsafe.Sizeof(int16(0))))
var UINT16 = AT(TYPE_UINT16, TYPE_NUM, uint32(unsafe.Sizeof(uint16(0))))
var INT32 = AT(TYPE_INT32, TYPE_NUM, uint32(unsafe.Sizeof(int32(0))))
var UINT32 = AT(TYPE_UINT32, TYPE_NUM, uint32(unsafe.Sizeof(uint32(0))))
var INT64 = AT(TYPE_INT64, TYPE_NUM, uint32(unsafe.Sizeof(int64(0))))
var UINT64 = AT(TYPE_UINT64, TYPE_NUM, uint32(unsafe.Sizeof(uint64(0))))

// typedef short unsigned int umode_t;
var UMODE_T = UINT16.Clone()

// unsigned long
var ULONG = UINT64.Clone()

var STRING = AT(TYPE_STRING, TYPE_STRING, uint32(unsafe.Sizeof(uint64(0))))
var STRING_ARR = AT(TYPE_STRING_ARR, TYPE_STRING_ARR, uint32(unsafe.Sizeof(uint64(0))))
var POINTER = AT(TYPE_POINTER, TYPE_POINTER, uint32(unsafe.Sizeof(uint64(0))))
var TIMESPEC = AT(TYPE_TIMESPEC, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Timespec{})))
var STAT = AT(TYPE_STAT, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Stat_t{})))
var STATFS = AT(TYPE_STATFS, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Statfs_t{})))
var SIGACTION = AT(TYPE_SIGACTION, TYPE_STRUCT, uint32(unsafe.Sizeof(Sigaction{})))
var UTSNAME = AT(TYPE_UTSNAME, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Utsname{})))
var SOCKADDR = AT(TYPE_SOCKADDR, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.RawSockaddrUnix{})))
var RUSAGE = AT(TYPE_RUSAGE, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Rusage{})))
var IOVEC = AT(TYPE_IOVEC, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Iovec{})))
var EPOLLEVENT = AT(TYPE_EPOLLEVENT, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.EpollEvent{})))
var SYSINFO = AT(TYPE_SYSINFO, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Sysinfo_t{})))
var SIGINFO = AT(TYPE_SIGINFO, TYPE_STRUCT, uint32(unsafe.Sizeof(SigInfo{})))
var MSGHDR = AT(TYPE_MSGHDR, TYPE_STRUCT, uint32(unsafe.Sizeof(Msghdr{})))
var ITIMERSPEC = AT(TYPE_ITIMERSPEC, TYPE_STRUCT, uint32(unsafe.Sizeof(ItTmerspec{})))
var STACK_T = AT(TYPE_STACK_T, TYPE_STRUCT, uint32(unsafe.Sizeof(Stack_t{})))
var TIMEVAL = AT(TYPE_TIMEVAL, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Timeval{})))
var TIMEZONE = AT(TYPE_TIMEZONE, TYPE_STRUCT, uint32(unsafe.Sizeof(TimeZone_t{})))
var PTHREAD_ATTR = AT(TYPE_PTHREAD_ATTR, TYPE_STRUCT, uint32(binary.Size(Pthread_attr_t{})))

// 注意 ARRAY_T read_count item_persize 均为 1
var ARRAY_T = AT(TYPE_ARRAY, TYPE_ARRAY, 1)

// 常规数组
// item_persize 就是数组元素的大小
// read_count 则根据具体需要设定
var INT32_ARR = ARRAY_T.NewArrayArgType(TYPE_ARRAY_INT32, uint32(unsafe.Sizeof(int32(0))))
var UINT32_ARR = ARRAY_T.NewArrayArgType(TYPE_ARRAY_UINT32, uint32(unsafe.Sizeof(uint32(0))))

// 特定类型的数组
// 例如 pipe2 的 pipefd 参数 是一个 int[2]
// 那么设定 read_count 为2
var PIPEFD_T = INT32_ARR.NewReadCount(2)
var SOCKET_SV = INT32_ARR.NewReadCount(2)

// buffer数组
// 单个元素长度都是 1
// 但是为了在输出结果的时候进行区分 重置其类型
var BUFFER_T = ARRAY_T.NewAliasType(TYPE_BUFFER)

// BUFFER 的一个特点 其长度可能由某个参数所控制
var READ_BUFFER_T = BUFFER_T.NewCountIndex(2)
var WRITE_BUFFER_T = BUFFER_T.NewCountIndex(2)
var MPROTECT_BUFFER_T = BUFFER_T.NewCountIndex(1)

var IOVEC_T = IOVEC.NewCountIndex(2)

// 64 位下这个是 unsigned long sig[_NSIG_WORDS]
// #define _NSIG       64
// #define _NSIG_BPW   __BITS_PER_LONG
// #define _NSIG_WORDS (_NSIG / _NSIG_BPW)
// unsigned long -> 4
var SIGSET = AT(TYPE_SIGSET, TYPE_STRUCT, 4*8)
var POLLFD = AT(TYPE_POLLFD, TYPE_STRUCT, uint32(unsafe.Sizeof(Pollfd{})))

func init() {
	// 结构体成员相关 某些参数的成员是指针类型的情况
	// Register(&PArgs{"sockaddr", []PArg{{"sockfd",EXP_INT}, {"addr", SOCKADDR}, {"addrlen", UINT32}}})

	// syscall相关
	Register(&SArgs{0, PA("io_setup", []PArg{A("nr_events", UINT), A("ctx_idp", POINTER)})})
	Register(&SArgs{1, PA("io_destroy", []PArg{A("ctx", POINTER)})})
	Register(&SArgs{2, PA("io_submit", []PArg{A("ctx_id", POINTER), A("nr", UINT64), A("iocbpp", POINTER)})})
	Register(&SArgs{3, PA("io_cancel", []PArg{A("ctx_id", POINTER), A("iocb", POINTER), A("result", POINTER)})})
	Register(&SArgs{4, PA("io_getevents", []PArg{A("ctx_id", POINTER), A("min_nr", UINT64), A("nr", UINT64), A("events", POINTER), A("timeout", TIMESPEC)})})
	Register(&SArgs{5, PA("setxattr", []PArg{A("pathname", STRING), A("name", STRING), A("value", POINTER), A("size", INT), A("flags", EXP_INT)})})
	Register(&SArgs{6, PA("lsetxattr", []PArg{A("pathname", STRING), A("name", STRING), A("value", POINTER), A("size", INT), A("flags", EXP_INT)})})
	Register(&SArgs{7, PA("fsetxattr", []PArg{A("fd", EXP_INT), A("name", STRING), A("value", POINTER), A("size", INT), A("flags", EXP_INT)})})
	Register(&SArgs{8, PA("getxattr", []PArg{A("path", STRING), A("name", STRING), A("value", POINTER), A("size", INT)})})
	Register(&SArgs{9, PA("lgetxattr", []PArg{A("path", STRING), A("name", STRING), A("value", POINTER), A("size", INT)})})
	Register(&SArgs{10, PA("fgetxattr", []PArg{A("fd", EXP_INT), A("name", STRING), A("value", POINTER), A("size", INT)})})
	Register(&SArgs{11, PA("listxattr", []PArg{A("pathname", STRING), A("list", STRING), A("size", INT)})})
	Register(&SArgs{12, PA("llistxattr", []PArg{A("pathname", STRING), A("list", STRING), A("size", INT)})})
	Register(&SArgs{13, PA("flistxattr", []PArg{A("fd", EXP_INT), A("list", STRING), A("size", INT)})})
	Register(&SArgs{14, PA("removexattr", []PArg{A("pathname", STRING), A("name", STRING)})})
	Register(&SArgs{15, PA("lremovexattr", []PArg{A("pathname", STRING), A("name", STRING)})})
	Register(&SArgs{16, PA("fremovexattr", []PArg{A("fd", EXP_INT), A("name", STRING)})})
	Register(&SArgs{17, PA("getcwd", []PArg{B("buf", STRING), A("size", UINT64)})})
	Register(&SArgs{18, PA("lookup_dcookie", []PArg{A("cookie", INT), B("buffer", STRING), A("len", INT)})})
	Register(&SArgs{19, PA("eventfd2", []PArg{A("initval", INT), A("flags", EXP_INT)})})
	Register(&SArgs{20, PAI("epoll_create1", []PArg{A("flags", EXP_INT)})})
	Register(&SArgs{21, PAI("epoll_ctl", []PArg{A("epfd", INT), A("op", INT), A("fd", EXP_INT), A("event", EPOLLEVENT)})})
	Register(&SArgs{22, PAI("epoll_pwait", []PArg{A("epfd", INT), A("events", POINTER), A("maxevents", INT), A("timeout", INT), A("sigmask", SIGSET)})})
	Register(&SArgs{23, PAI("dup", []PArg{A("oldfd", EXP_INT)})})
	Register(&SArgs{24, PAI("dup3", []PArg{A("oldfd", EXP_INT), A("newfd", EXP_INT), A("flags", EXP_INT)})})
	Register(&SArgs{25, PA("fcntl", []PArg{A("fd", EXP_INT), A("cmd", INT), A("arg", INT)})})
	Register(&SArgs{26, PA("inotify_init1", []PArg{A("flags", EXP_INT)})})
	Register(&SArgs{27, PA("inotify_add_watch", []PArg{A("fd", EXP_INT), A("pathname", STRING), A("mask", INT)})})
	Register(&SArgs{28, PA("inotify_rm_watch", []PArg{A("fd", EXP_INT), A("wd", INT)})})
	Register(&SArgs{29, PA("ioctl", []PArg{A("fd", EXP_INT), A("request", UINT64), A("arg0", INT), A("arg1", INT), A("arg2", INT), A("arg3", INT)})})
	Register(&SArgs{30, PA("ioprio_set", []PArg{A("which", INT), A("who", INT), A("ioprio", INT)})})
	Register(&SArgs{31, PA("ioprio_get", []PArg{A("which", INT), A("who", INT)})})
	Register(&SArgs{32, PA("flock", []PArg{A("fd", EXP_INT), A("operation", INT)})})
	Register(&SArgs{33, PA("mknodat", []PArg{A("dfd", INT), A("filename", STRING), A("mode", UMODE_T), A("dev", INT)})})
	Register(&SArgs{34, PA("mkdirat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("mode", UMODE_T)})})
	Register(&SArgs{35, PA("unlinkat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{36, PA("symlinkat", []PArg{A("target", STRING), A("newdirfd", INT), A("linkpath", STRING)})})
	Register(&SArgs{37, PA("linkat", []PArg{A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{38, PA("renameat", []PArg{A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING)})})
	Register(&SArgs{39, PA("umount2", []PArg{A("target", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{40, PA("mount", []PArg{A("source", INT), A("target", STRING), A("filesystemtype", STRING), A("mountflags", INT), A("data", POINTER)})})
	Register(&SArgs{41, PA("pivot_root", []PArg{A("new_root", STRING), A("put_old", STRING)})})
	Register(&SArgs{42, PA("nfsservctl", []PArg{A("cmd", INT), A("argp", POINTER), A("resp", POINTER)})})
	Register(&SArgs{43, PA("statfs", []PArg{A("path", STRING), B("buf", STATFS)})})
	Register(&SArgs{44, PA("fstatfs", []PArg{A("fd", EXP_INT), B("buf", STATFS)})})
	Register(&SArgs{45, PA("truncate", []PArg{A("path", STRING), A("length", INT)})})
	Register(&SArgs{46, PA("ftruncate", []PArg{A("fd", EXP_INT), A("length", INT)})})
	Register(&SArgs{47, PA("fallocate", []PArg{A("fd", EXP_INT), A("mode", EXP_INT), A("offset", INT), A("len", INT)})})
	Register(&SArgs{48, PA("faccessat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("flags", EXP_INT), A("mode", EXP_INT)})})
	Register(&SArgs{49, PA("chdir", []PArg{A("path", STRING)})})
	Register(&SArgs{50, PA("fchdir", []PArg{A("fd", EXP_INT)})})
	Register(&SArgs{51, PA("chroot", []PArg{A("path", STRING)})})
	Register(&SArgs{52, PA("fchmod", []PArg{A("fd", EXP_INT), A("mode", UMODE_T)})})
	Register(&SArgs{53, PA("fchmodat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("mode", UMODE_T), A("flags", EXP_INT)})})
	Register(&SArgs{54, PA("fchownat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("owner", INT), A("group", INT), A("flags", EXP_INT)})})
	Register(&SArgs{55, PA("fchown", []PArg{A("fd", EXP_INT), A("owner", INT), A("group", INT)})})
	Register(&SArgs{56, PAI("openat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("flags", EXP_INT), A("mode", UMODE_T)})})
	Register(&SArgs{57, PA("close", []PArg{A("fd", EXP_INT)})})
	Register(&SArgs{58, PA("vhangup", []PArg{})})
	Register(&SArgs{59, PA("pipe2", []PArg{B("pipefd", PIPEFD_T), A("flags", EXP_INT)})})
	Register(&SArgs{60, PA("quotactl", []PArg{A("cmd", INT), A("special", STRING), A("id", INT), A("addr", INT)})})
	Register(&SArgs{61, PA("getdents64", []PArg{A("fd", EXP_INT), B("dirp", POINTER), A("count", INT)})})
	Register(&SArgs{62, PA("lseek", []PArg{A("fd", EXP_INT), A("offset", INT), A("whence", INT)})})
	Register(&SArgs{63, PA("read", []PArg{A("fd", EXP_INT), B("buf", READ_BUFFER_T), A("count", INT)})})
	Register(&SArgs{64, PA("write", []PArg{A("fd", EXP_INT), A("buf", WRITE_BUFFER_T), A("count", INT)})})
	Register(&SArgs{65, PA("readv", []PArg{A("fd", EXP_INT), B("iov", IOVEC_T), A("iovcnt", INT)})})
	Register(&SArgs{66, PA("writev", []PArg{A("fd", EXP_INT), A("iov", IOVEC_T), A("iovcnt", INT)})})
	Register(&SArgs{67, PA("pread64", []PArg{A("fd", EXP_INT), B("buf", READ_BUFFER_T), A("count", INT), A("offset", INT)})})
	Register(&SArgs{68, PA("pwrite64", []PArg{A("fd", EXP_INT), A("buf", WRITE_BUFFER_T), A("count", INT), A("offset", INT)})})
	Register(&SArgs{69, PA("preadv", []PArg{A("fd", EXP_INT), B("iov", IOVEC_T), A("iovcnt", INT), A("offset", INT)})})
	Register(&SArgs{70, PA("pwritev", []PArg{A("fd", EXP_INT), A("iov", IOVEC_T), A("iovcnt", INT), A("offset", INT)})})
	Register(&SArgs{71, PA("sendfile", []PArg{A("out_fd", INT), A("in_fd", INT), A("offset", INT), A("count", INT)})})
	Register(&SArgs{72, PA("pselect6", []PArg{A("n", INT), A("inp", POINTER), A("outp", POINTER), A("exp", POINTER), A("tsp", TIMESPEC), A("sig", POINTER)})})
	Register(&SArgs{73, PA("ppoll", []PArg{A("fds", POLLFD), A("nfds", INT), A("tmo_p", TIMESPEC), A("sigmask", INT)})})
	Register(&SArgs{74, PA("signalfd4", []PArg{A("ufd", INT), A("user_mask", POINTER), A("sizemask", INT), A("flags", EXP_INT)})})
	Register(&SArgs{75, PA("vmsplice", []PArg{A("fd", EXP_INT), A("uiov", IOVEC_T), A("nr_segs", INT), A("flags", EXP_INT)})})
	Register(&SArgs{76, PA("splice", []PArg{A("fd_in", INT), A("off_in", INT), A("fd_out", INT), A("off_out", INT), A("len", INT), A("flags", EXP_INT)})})
	Register(&SArgs{77, PA("tee", []PArg{A("fdin", INT), A("fdout", INT), A("len", INT), A("flags", EXP_INT)})})
	Register(&SArgs{78, PA("readlinkat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), B("buf", STRING), A("bufsiz", INT)})})
	Register(&SArgs{79, PA("newfstatat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), B("statbuf", STAT), A("flags", EXP_INT)})})
	Register(&SArgs{80, PA("fstat", []PArg{A("fd", EXP_INT), B("statbuf", STAT)})})
	Register(&SArgs{81, PArgs{"sync", B("ret", NONE), []PArg{}}})
	Register(&SArgs{82, PA("fsync", []PArg{A("fd", EXP_INT)})})
	Register(&SArgs{83, PA("fdatasync", []PArg{A("fd", EXP_INT)})})
	Register(&SArgs{84, PA("sync_file_range", []PArg{A("fd", EXP_INT), A("offset", INT), A("nbytes", INT), A("flags", EXP_INT)})})
	Register(&SArgs{85, PA("timerfd_create", []PArg{A("clockid", INT), A("flags", EXP_INT)})})
	Register(&SArgs{86, PA("timerfd_settime", []PArg{A("fd", EXP_INT), A("flags", EXP_INT), A("new_value", ITIMERSPEC), A("old_value", ITIMERSPEC)})})
	Register(&SArgs{87, PA("timerfd_gettime", []PArg{A("fd", EXP_INT), B("curr_value", ITIMERSPEC)})})
	Register(&SArgs{88, PA("utimensat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("times", ITIMERSPEC), A("flags", EXP_INT)})})
	Register(&SArgs{89, PA("acct", []PArg{A("name", STRING)})})
	Register(&SArgs{90, PA("capget", []PArg{A("header", POINTER), A("dataptr", POINTER)})})
	Register(&SArgs{91, PA("capset", []PArg{A("header", POINTER), A("data", POINTER)})})
	Register(&SArgs{92, PA("personality", []PArg{A("personality", INT)})})
	Register(&SArgs{93, PArgs{"exit", B("ret", NONE), []PArg{A("status", INT)}}})
	Register(&SArgs{94, PArgs{"exit_group", B("ret", NONE), []PArg{A("status", INT)}}})
	Register(&SArgs{95, PA("waitid", []PArg{A("which", INT), A("upid", INT), A("infop", SIGINFO), A("options", INT), A("ru", RUSAGE)})})
	Register(&SArgs{96, PA("set_tid_address", []PArg{A("tidptr", POINTER)})})
	Register(&SArgs{97, PA("unshare", []PArg{A("unshare_flags", INT)})})
	Register(&SArgs{98, PA("futex", []PArg{A("uaddr", INT), A("futex_op", INT), A("val", INT), A("timeout", TIMESPEC)})})
	Register(&SArgs{99, PA("set_robust_list", []PArg{A("head", POINTER), A("len", INT)})})
	Register(&SArgs{100, PA("get_robust_list", []PArg{A("pid", INT), A("head_ptr", POINTER), A("len_ptr", INT)})})
	Register(&SArgs{101, PA("nanosleep", []PArg{A("req", TIMESPEC), A("rem", TIMESPEC)})})
	Register(&SArgs{102, PA("getitimer", []PArg{A("which", INT), A("value", POINTER)})})
	Register(&SArgs{103, PA("setitimer", []PArg{A("which", INT), A("value", POINTER), A("ovalue", POINTER)})})
	Register(&SArgs{104, PA("kexec_load", []PArg{A("entry", INT), A("nr_segments", INT), A("segments", POINTER), A("flags", EXP_INT)})})
	Register(&SArgs{105, PA("init_module", []PArg{A("umod", POINTER), A("len", INT), A("uargs", STRING)})})
	Register(&SArgs{106, PA("delete_module", []PArg{A("name_user", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{107, PA("timer_create", []PArg{A("which_clock", INT), A("timer_event_spec", POINTER), A("created_timer_id", INT)})})
	Register(&SArgs{108, PA("timer_gettime", []PArg{A("timer_id", INT), A("setting", POINTER)})})
	Register(&SArgs{109, PA("timer_getoverrun", []PArg{A("timer_id", INT)})})
	Register(&SArgs{110, PA("timer_settime", []PArg{A("timer_id", INT), A("flags", EXP_INT), A("new_setting", POINTER), A("old_setting", POINTER)})})
	Register(&SArgs{111, PA("timer_delete", []PArg{A("timer_id", INT)})})
	Register(&SArgs{112, PA("clock_settime", []PArg{A("clockid", INT), A("tp", TIMESPEC)})})
	Register(&SArgs{113, PA("clock_gettime", []PArg{A("clockid", INT), B("tp", TIMESPEC)})})
	Register(&SArgs{114, PA("clock_getres", []PArg{A("clockid", INT), B("res", TIMESPEC)})})
	Register(&SArgs{115, PA("clock_nanosleep", []PArg{A("clockid", INT), A("flags", EXP_INT), A("request", TIMESPEC), B("remain", TIMESPEC)})})
	Register(&SArgs{116, PA("syslog", []PArg{A("type", INT), A("bufp", STRING), A("len", INT)})})
	Register(&SArgs{117, PA("ptrace", []PArg{A("request", INT), A("pid", EXP_INT), A("addr", POINTER), A("data", POINTER)})})
	Register(&SArgs{118, PA("sched_setparam", []PArg{A("pid", INT), A("param", POINTER)})})
	Register(&SArgs{119, PA("sched_setscheduler", []PArg{A("pid", INT), A("policy", INT), A("param", POINTER)})})
	Register(&SArgs{120, PA("sched_getscheduler", []PArg{A("pid", INT)})})
	Register(&SArgs{121, PA("sched_getparam", []PArg{A("pid", INT), B("param", POINTER)})})
	Register(&SArgs{122, PA("sched_setaffinity", []PArg{A("pid", INT), A("cpusetsize", INT), A("mask", POINTER)})})
	Register(&SArgs{123, PA("sched_getaffinity", []PArg{A("pid", INT), A("cpusetsize", INT), B("mask", POINTER)})})
	Register(&SArgs{124, PA("sched_yield", []PArg{})})
	Register(&SArgs{125, PA("sched_get_priority_max", []PArg{A("policy", INT)})})
	Register(&SArgs{126, PA("sched_get_priority_min", []PArg{A("policy", INT)})})
	Register(&SArgs{127, PA("sched_rr_get_interval", []PArg{A("pid", INT), A("interval", TIMESPEC)})})
	Register(&SArgs{128, PA("restart_syscall", []PArg{})})
	Register(&SArgs{129, PA("kill", []PArg{A("pid", INT), A("sig", INT)})})
	Register(&SArgs{130, PA("tkill", []PArg{A("tid", INT), A("sig", INT)})})
	Register(&SArgs{131, PA("tgkill", []PArg{A("tgid", INT), A("tid", INT), A("sig", INT)})})
	Register(&SArgs{132, PA("sigaltstack", []PArg{A("ss", STACK_T), A("old_ss", STACK_T)})})
	Register(&SArgs{133, PA("rt_sigsuspend", []PArg{A("mask", SIGSET)})})
	Register(&SArgs{134, PA("rt_sigaction", []PArg{A("signum", INT), A("act", SIGACTION), A("oldact", SIGACTION)})})
	Register(&SArgs{135, PA("rt_sigprocmask", []PArg{A("how", INT), A("set", UINT64), A("oldset", UINT64), A("sigsetsize", INT)})})
	Register(&SArgs{136, PA("rt_sigpending", []PArg{A("uset", POINTER), A("sigsetsize", INT)})})
	Register(&SArgs{137, PA("rt_sigtimedwait", []PArg{A("uthese", POINTER), A("uinfo", SIGINFO), A("uts", TIMESPEC), A("sigsetsize", INT)})})
	Register(&SArgs{138, PA("rt_sigqueueinfo", []PArg{A("pid", INT), A("sig", INT), A("uinfo", SIGINFO)})})
	Register(&SArgs{139, PA("rt_sigreturn", []PArg{A("mask", INT)})})
	Register(&SArgs{140, PA("setpriority", []PArg{A("which", INT), A("who", INT), A("prio", INT)})})
	Register(&SArgs{141, PA("getpriority", []PArg{A("which", INT), A("who", INT)})})
	Register(&SArgs{142, PA("reboot", []PArg{A("magic1", INT), A("magic2", INT), A("cmd", INT), A("arg", POINTER)})})
	Register(&SArgs{143, PA("setregid", []PArg{A("rgid", INT), A("egid", INT)})})
	Register(&SArgs{144, PA("setgid", []PArg{A("gid", INT)})})
	Register(&SArgs{145, PA("setreuid", []PArg{A("ruid", INT), A("euid", INT)})})
	Register(&SArgs{146, PA("setuid", []PArg{A("uid", INT)})})
	Register(&SArgs{147, PA("setresuid", []PArg{A("ruid", INT), A("euid", INT), A("suid", INT)})})
	Register(&SArgs{148, PA("getresuid", []PArg{A("ruidp", INT), A("euidp", INT), A("suidp", INT)})})
	Register(&SArgs{149, PA("setresgid", []PArg{A("rgid", INT), A("egid", INT), A("sgid", INT)})})
	Register(&SArgs{150, PA("getresgid", []PArg{A("rgidp", INT), A("egidp", INT), A("sgidp", INT)})})
	Register(&SArgs{151, PA("setfsuid", []PArg{A("uid", INT)})})
	Register(&SArgs{152, PA("setfsgid", []PArg{A("gid", INT)})})
	Register(&SArgs{153, PA("times", []PArg{A("tbuf", POINTER)})})
	Register(&SArgs{154, PA("setpgid", []PArg{A("pid", INT), A("pgid", INT)})})
	Register(&SArgs{155, PA("getpgid", []PArg{A("pid", INT)})})
	Register(&SArgs{156, PA("getsid", []PArg{A("pid", INT)})})
	Register(&SArgs{157, PA("setsid", []PArg{})})
	Register(&SArgs{158, PA("getgroups", []PArg{A("gidsetsize", INT), A("grouplist", INT)})})
	Register(&SArgs{159, PA("setgroups", []PArg{A("gidsetsize", INT), A("grouplist", INT)})})
	Register(&SArgs{160, PA("uname", []PArg{B("buf", UTSNAME)})})
	Register(&SArgs{161, PA("sethostname", []PArg{A("name", STRING), A("len", INT)})})
	Register(&SArgs{162, PA("setdomainname", []PArg{A("name", STRING), A("len", INT)})})
	Register(&SArgs{163, PA("getrlimit", []PArg{A("resource", INT), B("rlim", POINTER)})})
	Register(&SArgs{164, PA("setrlimit", []PArg{A("resource", UTSNAME), A("rlim", POINTER)})})
	Register(&SArgs{165, PA("getrusage", []PArg{A("who", INT), B("usage", RUSAGE)})})
	Register(&SArgs{166, PA("umask", []PArg{A("mode", EXP_INT)})})
	Register(&SArgs{167, PA("prctl", []PArg{A("option", INT), A("arg2", UINT64), A("arg3", UINT64), A("arg4", UINT64), A("arg5", UINT64)})})
	Register(&SArgs{168, PA("getcpu", []PArg{A("cpup", INT), A("nodep", INT), A("unused", POINTER)})})
	Register(&SArgs{169, PA("gettimeofday", []PArg{B("tv", TIMEVAL), B("tz", TIMEZONE)})})
	Register(&SArgs{170, PA("settimeofday", []PArg{A("tv", TIMEVAL), A("tz", TIMEZONE)})})
	Register(&SArgs{171, PA("adjtimex", []PArg{A("txc_p", POINTER)})})
	Register(&SArgs{172, PA("getpid", []PArg{})})
	Register(&SArgs{173, PA("getppid", []PArg{})})
	Register(&SArgs{174, PA("getuid", []PArg{})})
	Register(&SArgs{175, PA("geteuid", []PArg{})})
	Register(&SArgs{176, PA("getgid", []PArg{})})
	Register(&SArgs{177, PA("getegid", []PArg{})})
	Register(&SArgs{178, PA("gettid", []PArg{})})
	Register(&SArgs{179, PA("sysinfo", []PArg{B("info", SYSINFO)})})
	Register(&SArgs{180, PA("mq_open", []PArg{A("u_name", STRING), A("oflag", INT), A("mode", UMODE_T), A("u_attr", POINTER)})})
	Register(&SArgs{181, PA("mq_unlink", []PArg{A("u_name", STRING)})})
	Register(&SArgs{182, PA("mq_timedsend", []PArg{A("mqdes", INT), A("u_msg_ptr", STRING), A("msg_len", INT), A("msg_prio", INT), A("u_abs_timeout", TIMESPEC)})})
	Register(&SArgs{183, PA("mq_timedreceive", []PArg{A("mqdes", INT), A("u_msg_ptr", STRING), A("msg_len", INT), A("u_msg_prio", INT), A("u_abs_timeout", TIMESPEC)})})
	Register(&SArgs{184, PA("mq_notify", []PArg{A("mqdes", INT), A("u_notification", POINTER)})})
	Register(&SArgs{185, PA("mq_getsetattr", []PArg{A("mqdes", INT), A("u_mqstat", POINTER), A("u_omqstat", POINTER)})})
	Register(&SArgs{186, PA("msgget", []PArg{A("key", INT), A("msgflg", INT)})})
	Register(&SArgs{187, PA("msgctl", []PArg{A("msqid", INT), A("cmd", INT), A("buf", POINTER)})})
	Register(&SArgs{188, PA("msgrcv", []PArg{A("msqid", INT), A("msgp", POINTER), A("msgsz", INT), A("msgtyp", UINT64), A("msgflg", INT)})})
	Register(&SArgs{189, PA("msgsnd", []PArg{A("msqid", INT), A("msgp", POINTER), A("msgsz", INT), A("msgflg", INT)})})
	Register(&SArgs{190, PA("semget", []PArg{A("key", INT), A("nsems", INT), A("semflg", INT)})})
	Register(&SArgs{191, PA("semctl", []PArg{A("semid", INT), A("semnum", INT), A("cmd", INT), A("arg", INT)})})
	Register(&SArgs{192, PA("semtimedop", []PArg{A("semid", INT), A("tsops", POINTER), A("nsops", INT), A("timeout", TIMESPEC)})})
	Register(&SArgs{193, PA("semop", []PArg{A("semid", INT), A("tsops", POINTER), A("nsops", INT)})})
	Register(&SArgs{194, PA("shmget", []PArg{A("key", INT), A("size", INT), A("shmflg", INT)})})
	Register(&SArgs{195, PA("shmctl", []PArg{A("shmid", INT), A("cmd", INT), A("buf", POINTER)})})
	Register(&SArgs{196, PA("shmat", []PArg{A("shmid", INT), A("shmaddr", POINTER), A("shmflg", INT)})})
	Register(&SArgs{197, PA("shmdt", []PArg{A("shmaddr", POINTER)})})
	Register(&SArgs{198, PAI("socket", []PArg{A("domain", EXP_INT), A("type", EXP_INT), A("protocol", EXP_INT)})})
	Register(&SArgs{199, PAI("socketpair", []PArg{A("domain", EXP_INT), A("type", EXP_INT), A("protocol", EXP_INT), B("sv", SOCKET_SV)})})
	Register(&SArgs{200, PAI("bind", []PArg{A("sockfd", EXP_INT), A("addr", SOCKADDR), A("addrlen", EXP_INT)})})
	Register(&SArgs{201, PAI("listen", []PArg{A("sockfd", EXP_INT), A("backlog", INT)})})
	Register(&SArgs{202, PAI("accept", []PArg{A("sockfd", EXP_INT), A("addr", SOCKADDR), A("addrlen", EXP_INT)})})
	Register(&SArgs{203, PAI("connect", []PArg{A("sockfd", EXP_INT), A("addr", SOCKADDR), A("addrlen", EXP_INT)})})
	Register(&SArgs{204, PAI("getsockname", []PArg{A("sockfd", EXP_INT), B("addr", SOCKADDR), A("addrlen", EXP_INT)})})
	Register(&SArgs{205, PAI("getpeername", []PArg{A("sockfd", EXP_INT), B("addr", SOCKADDR), A("addrlen", EXP_INT)})})
	Register(&SArgs{206, PAI("sendto", []PArg{A("sockfd", EXP_INT), A("buf", READ_BUFFER_T), A("len", INT), A("flags", EXP_INT), A("dest_addr", SOCKADDR), A("addrlen", EXP_INT)})})
	Register(&SArgs{207, PAI("recvfrom", []PArg{A("sockfd", EXP_INT), B("buf", WRITE_BUFFER_T), A("len", INT), A("flags", EXP_INT)})})
	Register(&SArgs{208, PAI("setsockopt", []PArg{A("sockfd", EXP_INT), A("level", INT), A("optname", INT), A("optval", INT), A("optlen", INT)})})
	Register(&SArgs{209, PAI("getsockopt", []PArg{A("sockfd", EXP_INT), A("level", INT), A("optname", INT), B("optval", INT), A("optlen", POINTER)})})
	Register(&SArgs{210, PAI("shutdown", []PArg{A("sockfd", EXP_INT), A("how", INT)})})
	Register(&SArgs{211, PAI("sendmsg", []PArg{A("sockfd", EXP_INT), A("msg", MSGHDR), A("flags", EXP_INT)})})
	Register(&SArgs{212, PAI("recvmsg", []PArg{A("sockfd", EXP_INT), B("msg", MSGHDR), A("flags", EXP_INT)})})
	Register(&SArgs{213, PAI("readahead", []PArg{A("fd", EXP_INT), A("offset", INT), A("count", INT)})})
	Register(&SArgs{214, PA("brk", []PArg{A("brk", INT)})})
	Register(&SArgs{215, PAI("munmap", []PArg{A("addr", INT64), A("length", INT)})})
	Register(&SArgs{216, PA("mremap", []PArg{A("old_address", POINTER), A("old_size", INT), A("new_size", INT), A("flags", EXP_INT)})})
	Register(&SArgs{217, PA("add_key", []PArg{A("_type", STRING), A("_description", STRING), A("_payload", POINTER), A("plen", INT), A("ringid", INT)})})
	Register(&SArgs{218, PA("request_key", []PArg{A("_type", STRING), A("_description", STRING), A("_callout_info", STRING), A("destringid", INT)})})
	Register(&SArgs{219, PA("keyctl", []PArg{A("option", INT), A("arg2", INT), A("arg3", INT), A("arg4", INT), A("arg5", INT)})})
	Register(&SArgs{220, PA("clone", []PArg{A("fn", POINTER), A("stack", POINTER), A("flags", EXP_INT), A("arg0", INT), A("arg1", INT), A("arg2", INT)})})
	Register(&SArgs{221, PA("execve", []PArg{A("pathname", STRING), A("argv", STRING_ARR), A("envp", STRING_ARR)})})
	Register(&SArgs{222, PA("mmap", []PArg{B("addr", POINTER), A("length", INT), A("prot", EXP_INT), A("flags", EXP_INT), A("fd", EXP_INT), A("offset", INT)})})
	Register(&SArgs{223, PA("fadvise64", []PArg{A("fd", EXP_INT), A("offset", INT), A("len", INT), A("advice", INT)})})
	Register(&SArgs{224, PA("swapon", []PArg{A("specialfile", STRING), A("swap_flags", INT)})})
	Register(&SArgs{225, PA("swapoff", []PArg{A("specialfile", STRING)})})
	Register(&SArgs{226, PAI("mprotect", []PArg{A("addr", POINTER), A("length", INT), A("prot", EXP_INT)})})
	Register(&SArgs{227, PA("msync", []PArg{A("addr", POINTER), A("length", INT), A("flags", EXP_INT)})})
	Register(&SArgs{228, PA("mlock", []PArg{A("start", INT), A("len", INT)})})
	Register(&SArgs{229, PA("munlock", []PArg{A("start", INT), A("len", INT)})})
	Register(&SArgs{230, PA("mlockall", []PArg{A("flags", EXP_INT)})})
	Register(&SArgs{231, PA("munlockall", []PArg{})})
	Register(&SArgs{232, PA("mincore", []PArg{A("start", INT), A("len", INT), A("vec", STRING)})})
	Register(&SArgs{233, PA("madvise", []PArg{A("addr", POINTER), A("len", INT), A("advice", INT)})})
	Register(&SArgs{234, PA("remap_file_pages", []PArg{A("start", INT), A("size", INT), A("prot", EXP_INT), A("pgoff", INT), A("flags", EXP_INT)})})
	Register(&SArgs{235, PA("mbind", []PArg{A("start", ULONG), A("len", ULONG), A("mode", ULONG), A("nmask", INT), A("maxnode", INT), A("flags", EXP_INT)})})
	Register(&SArgs{236, PA("get_mempolicy", []PArg{A("policy", INT), A("nmask", INT), A("maxnode", INT), A("addr", INT), A("flags", EXP_INT)})})
	Register(&SArgs{237, PA("set_mempolicy", []PArg{A("mode", EXP_INT), A("nmask", INT), A("maxnode", INT)})})
	Register(&SArgs{238, PA("migrate_pages", []PArg{A("pid", INT), A("maxnode", INT), A("old_nodes", INT), A("new_nodes", INT)})})
	Register(&SArgs{239, PA("move_pages", []PArg{A("pid", INT), A("nr_pages", INT), A("pages", POINTER), A("nodes", INT), A("status", INT), A("flags", EXP_INT)})})
	Register(&SArgs{240, PA("rt_tgsigqueueinfo", []PArg{A("tgid", INT), A("tid", INT), A("sig", INT), A("siginfo", SIGINFO)})})
	Register(&SArgs{241, PA("perf_event_open", []PArg{A("attr_uptr", POINTER), A("pid", INT), A("cpu", INT), A("group_fd", INT), A("flags", EXP_INT)})})
	Register(&SArgs{242, PAI("accept4", []PArg{A("sockfd", EXP_INT), A("addr", SOCKADDR), A("addrlen", EXP_INT), A("flags", EXP_INT)})})
	Register(&SArgs{243, PA("recvmmsg", []PArg{A("fd", EXP_INT), A("mmsg", POINTER), A("vlen", INT), A("flags", EXP_INT), A("timeout", TIMESPEC)})})
	Register(&SArgs{260, PA("wait4", []PArg{A("pid", INT), A("wstatus", POINTER), A("options", INT), B("rusage", RUSAGE)})})
	Register(&SArgs{261, PA("prlimit64", []PArg{A("pid", INT), A("resource", INT), A("new_rlim", POINTER), A("old_rlim", POINTER)})})
	Register(&SArgs{262, PA("fanotify_init", []PArg{A("flags", EXP_INT), A("event_f_flags", INT)})})
	Register(&SArgs{263, PA("fanotify_mark", []PArg{A("fanotify_fd", INT), A("flags", EXP_INT), A("mask", UINT64), A("dfd", INT), A("pathname", STRING)})})
	Register(&SArgs{264, PA("name_to_handle_at", []PArg{A("dfd", INT), A("name", STRING), A("handle", POINTER), A("mnt_id", INT), A("flag", INT)})})
	Register(&SArgs{265, PA("open_by_handle_at", []PArg{A("mountdirfd", INT), A("handle", POINTER), A("flags", EXP_INT)})})
	Register(&SArgs{266, PA("clock_adjtime", []PArg{A("which_clock", INT), A("utx", POINTER)})})
	Register(&SArgs{267, PA("syncfs", []PArg{A("fd", EXP_INT)})})
	Register(&SArgs{268, PA("setns", []PArg{A("fd", EXP_INT), A("flags", EXP_INT)})})
	Register(&SArgs{269, PA("sendmmsg", []PArg{A("fd", EXP_INT), A("mmsg", POINTER), A("vlen", INT), A("flags", EXP_INT)})})
	// 虽然处于内核 但是实测无法跨进程读取数据 所以对于这两个系统调用 只能获取 local_iov 的内容
	Register(&SArgs{270, PAI("process_vm_readv", []PArg{A("pid", EXP_INT), B("local_iov", IOVEC_T), A("liovcnt", INT), A("remote_iov", POINTER), A("riovcnt", INT), A("flags", EXP_INT)})})
	Register(&SArgs{271, PAI("process_vm_writev", []PArg{A("pid", EXP_INT), A("local_iov", IOVEC_T), A("liovcnt", INT), B("remote_iov", POINTER), A("riovcnt", INT), A("flags", EXP_INT)})})
	Register(&SArgs{272, PA("kcmp", []PArg{A("pid1", INT), A("pid2", INT), A("type", INT), A("idx1", INT), A("idx2", INT)})})
	Register(&SArgs{273, PA("finit_module", []PArg{A("fd", EXP_INT), A("uargs", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{274, PA("sched_setattr", []PArg{A("pid", INT), A("uattr", POINTER), A("flags", EXP_INT)})})
	Register(&SArgs{275, PA("sched_getattr", []PArg{A("pid", INT), A("uattr", POINTER), A("usize", INT), A("flags", EXP_INT)})})
	Register(&SArgs{276, PA("renameat2", []PArg{A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{277, PA("seccomp", []PArg{A("operation", INT), A("flags", EXP_INT), A("args", POINTER)})})
	Register(&SArgs{278, PA("getrandom", []PArg{B("buf", POINTER), A("buflen", INT), A("flags", EXP_INT)})})
	Register(&SArgs{279, PA("memfd_create", []PArg{A("name", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{280, PA("bpf", []PArg{A("cmd", INT), A("attr", POINTER), A("size", INT)})})
	Register(&SArgs{281, PA("execveat", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("argv", STRING_ARR), A("envp", STRING_ARR), A("flags", EXP_INT)})})
	Register(&SArgs{282, PA("userfaultfd", []PArg{A("flags", EXP_INT)})})
	Register(&SArgs{283, PA("membarrier", []PArg{A("cmd", INT), A("flags", POINTER), A("cpu_id", INT)})})
	Register(&SArgs{284, PA("mlock2", []PArg{A("start", INT), A("len", INT), A("flags", EXP_INT)})})
	Register(&SArgs{285, PA("copy_file_range", []PArg{A("fd_in", INT), A("off_in", INT), A("fd_out", INT), A("off_out", INT), A("len", INT), A("flags", EXP_INT)})})
	Register(&SArgs{286, PA("preadv2", []PArg{A("fd", EXP_INT), A("vec", POINTER), A("vlen", INT), A("pos_l", INT), A("pos_h", INT), A("flags", EXP_INT)})})
	Register(&SArgs{287, PA("pwritev2", []PArg{A("fd", EXP_INT), A("vec", POINTER), A("vlen", INT), A("pos_l", INT), A("pos_h", INT), A("flags", EXP_INT)})})
	Register(&SArgs{288, PA("pkey_mprotect", []PArg{B("addr", POINTER), A("length", INT), A("prot", EXP_INT), A("pkey", INT)})})
	Register(&SArgs{289, PA("pkey_alloc", []PArg{A("flags", EXP_INT), A("init_val", INT)})})
	Register(&SArgs{290, PA("pkey_free", []PArg{A("pkey", INT)})})
	Register(&SArgs{291, PA("statx", []PArg{A("dfd", INT), A("filename", STRING), A("flags", EXP_INT), A("mask", INT), A("buffer", POINTER)})})
	Register(&SArgs{292, PA("io_pgetevents", []PArg{A("ctx_id", POINTER), A("min_nr", UINT64), A("nr", UINT64), A("events", POINTER), A("timeout", TIMESPEC), A("usig", POINTER)})})
	Register(&SArgs{293, PA("rseq", []PArg{A("rseq", POINTER), A("rseq_len", INT), A("flags", EXP_INT), A("sig", INT)})})
	Register(&SArgs{294, PA("kexec_file_load", []PArg{A("kernel_fd", INT), A("initrd_fd", INT), A("cmdline_len", INT), A("cmdline_ptr", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{424, PA("pidfd_send_signal", []PArg{A("pidfd", INT), A("sig", INT), A("info", SIGINFO), A("flags", EXP_INT)})})
	Register(&SArgs{425, PA("io_uring_setup", []PArg{A("entries", INT), A("params", POINTER)})})
	Register(&SArgs{426, PA("io_uring_enter", []PArg{A("fd", EXP_INT), A("to_submit", INT), A("min_complete", INT), A("flags", EXP_INT), A("argp", POINTER), A("argsz", INT)})})
	Register(&SArgs{427, PA("io_uring_register", []PArg{A("fd", EXP_INT), A("opcode", INT), A("arg", POINTER), A("nr_args", INT)})})
	Register(&SArgs{428, PA("open_tree", []PArg{A("dfd", INT), A("filename", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{429, PA("move_mount", []PArg{A("from_dfd", INT), A("from_pathname", STRING), A("to_dfd", INT), A("to_pathname", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{430, PA("fsopen", []PArg{A("_fs_name", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{431, PA("fsconfig", []PArg{A("fd", EXP_INT), A("cmd", INT), A("_key", STRING), A("_value", POINTER), A("aux", INT)})})
	Register(&SArgs{432, PA("fsmount", []PArg{A("fs_fd", INT), A("flags", EXP_INT), A("attr_flags", INT)})})
	Register(&SArgs{433, PA("fspick", []PArg{A("dfd", INT), A("path", STRING), A("flags", EXP_INT)})})
	Register(&SArgs{434, PA("pidfd_open", []PArg{A("pid", INT), A("flags", EXP_INT)})})
	Register(&SArgs{435, PA("clone3", []PArg{A("uargs", POINTER), A("size", INT)})})
	Register(&SArgs{436, PA("close_range", []PArg{A("fd", EXP_INT), A("max_fd", INT), A("flags", EXP_INT)})})
	Register(&SArgs{437, PA("openat2", []PArg{A("dfd", INT), A("filename", STRING), A("how", POINTER), A("usize", INT)})})
	Register(&SArgs{438, PA("pidfd_getfd", []PArg{A("pidfd", INT), A("fd", EXP_INT), A("flags", EXP_INT)})})
	Register(&SArgs{439, PA("faccessat2", []PArg{A("dirfd", EXP_INT), A("pathname", STRING), A("flags", EXP_INT), A("mode", EXP_INT)})})
	Register(&SArgs{440, PA("process_madvise", []PArg{A("pidfd", INT), A("vec", POINTER), A("vlen", INT), A("behavior", INT), A("flags", EXP_INT)})})
	Register(&SArgs{441, PAI("epoll_pwait2", []PArg{A("epfd", INT), A("events", POINTER), A("maxevents", INT), A("timeout", TIMESPEC), A("sigmask", POINTER), A("sigsetsize", INT)})})
	Register(&SArgs{442, PA("mount_setattr", []PArg{A("dfd", INT), A("path", STRING), A("flags", EXP_INT), A("uattr", POINTER), A("usize", INT)})})
	Register(&SArgs{443, PA("quotactl_fd", []PArg{A("fd", EXP_INT), A("cmd", INT), A("id", INT), A("addr", POINTER)})})
	Register(&SArgs{444, PA("landlock_create_ruleset", []PArg{A("attr", POINTER), A("size", INT), A("flags", EXP_INT)})})
	Register(&SArgs{445, PA("landlock_add_rule", []PArg{A("ruleset_fd", INT), A("rule_type", INT), A("rule_attr", POINTER), A("flags", EXP_INT)})})
	Register(&SArgs{446, PA("landlock_restrict_self", []PArg{A("ruleset_fd", INT), A("flags", EXP_INT)})})
	Register(&SArgs{447, PA("memfd_secret", []PArg{A("flags", EXP_INT)})})
	Register(&SArgs{448, PA("process_mrelease", []PArg{A("pidfd", INT), A("flags", EXP_INT)})})
	Register(&SArgs{449, PA("futex_waitv", []PArg{A("waiters", POINTER), A("nr_futexes", INT), A("flags", EXP_INT), A("timeout", TIMESPEC), A("clockid", INT)})})
	Register(&SArgs{450, PA("set_mempolicy_home_node", []PArg{A("start", INT), A("len", INT), A("home_node", INT), A("flags", EXP_INT)})})
}
