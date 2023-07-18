package config

import (
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"
)

// 结合其他项目构想一种新的方案 便于后续增补各类结构体的数据解析
// 而不是依赖配置文件去转换 某种程度上来说 硬编码反而是更好的选择

const MAX_POINT_ARG_COUNT = 6

type ArgType struct {
	AliasType uint32
	Type      uint32
	Size      uint32
}

type FilterArgType struct {
	ReadFlag uint32
	ArgType
}

type PointArg struct {
	ArgName  string
	ReadFlag uint32
	ArgType
	ArgValue string
}

func (this *PointArg) SetValue(value string) {
	this.ArgValue = value
}

func (this *PointArg) AppendValue(value string) {
	this.ArgValue += value
}

type PArg = PointArg

func A(arg_name string, arg_type ArgType) PArg {
	return PArg{arg_name, SYS_ENTER, arg_type, "???"}
}

func B(arg_name string, arg_type ArgType) PArg {
	return PArg{arg_name, SYS_EXIT, arg_type, "???"}
}

type PointArgs struct {
	PointName string
	Ret       PointArg
	Args      []PointArg
}
type PArgs = PointArgs

func PA(nr string, args []PArg) PArgs {
	return PArgs{nr, B("ret", UINT64), args}
}

type PointTypes struct {
	Count      uint32
	ArgTypes   [MAX_POINT_ARG_COUNT]FilterArgType
	ArgTypeRet FilterArgType
}

type SysCallArgs struct {
	NR uint32
	PointArgs
}
type SArgs = SysCallArgs

func (this *PointArgs) Clone() IWatchPoint {
	args := new(PointArgs)
	args.PointName = this.PointName
	args.Ret = this.Ret
	args.Args = this.Args
	return args
}

func (this *PointArgs) Format() string {
	args, err := json.Marshal(this.Args)
	if err != nil {
		panic(fmt.Sprintf("Args Format err:%v", err))
	}
	return fmt.Sprintf("[%s] %d %s", this.PointName, len(this.Args), args)
}

func (this *PointArgs) Name() string {
	return this.PointName
}

func (this *PointArgs) GetConfig() *PointTypes {
	var point_arg_types [MAX_POINT_ARG_COUNT]FilterArgType
	for i := 0; i < MAX_POINT_ARG_COUNT; i++ {
		if i+1 > len(this.Args) {
			break
		}
		point_arg_types[i].ReadFlag = this.Args[i].ReadFlag
		point_arg_types[i].ArgType = this.Args[i].ArgType
	}
	var point_arg_type_ret FilterArgType
	point_arg_type_ret.ReadFlag = this.Ret.ReadFlag
	point_arg_type_ret.ArgType = this.Ret.ArgType
	config := &PointTypes{
		Count:      uint32(len(this.Args)),
		ArgTypes:   point_arg_types,
		ArgTypeRet: point_arg_type_ret,
	}
	return config
}

type IWatchPoint interface {
	Name() string
	Format() string
	Clone() IWatchPoint
}

func NewWatchPoint(name string) IWatchPoint {
	point := &PointArgs{}
	point.PointName = name
	return point
}

func NewSysCallWatchPoint(name string) IWatchPoint {
	point := &SysCallArgs{}
	return point
}

var watchpoints = make(map[string]IWatchPoint)
var nrwatchpoints = make(map[uint32]IWatchPoint)

func Register(p IWatchPoint) {
	if p == nil {
		panic("Register watchpoint is nil")
	}
	name := p.Name()
	if _, dup := watchpoints[name]; dup {
		panic(fmt.Sprintf("Register called twice for watchpoint %s", name))
	}
	watchpoints[name] = p
	// 给 syscall 单独维护一个 map 这样便于在解析的时候快速获取 point 配置
	nr_point, ok := (p).(*SysCallArgs)
	if ok {
		if _, dup := nrwatchpoints[nr_point.NR]; dup {
			panic(fmt.Sprintf("Register called twice for nrwatchpoints %s", name))
		}
		nrwatchpoints[nr_point.NR] = nr_point
	} else {
		panic(fmt.Sprintf("Register cast [%s] point to SysCallArgs failed", p.Name()))
	}
}

func GetAllWatchPoints() map[string]IWatchPoint {
	return watchpoints
}

func GetWatchPointByNR(nr uint32) IWatchPoint {
	m, f := nrwatchpoints[nr]
	if f {
		return m
	}
	return nil
}

func GetWatchPointByName(pointName string) IWatchPoint {
	m, f := watchpoints[pointName]
	if f {
		return m
	}
	return nil
}

type Sigaction struct {
	Sa_handler   uint64
	Sa_sigaction uint64
	Sa_mask      uint64
	Sa_flags     uint64
	Sa_restorer  uint64
}

type Pollfd struct {
	Fd      int
	Events  uint16
	Revents uint16
}

const (
	TYPE_NONE uint32 = iota
	TYPE_NUM
	TYPE_INT
	TYPE_UINT
	TYPE_UINT32
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
	TYPE_SIGSET
	TYPE_POLLFD
	TYPE_ARGASSIZE
)

const (
	FORBIDDEN uint32 = iota
	SYS_ENTER
	SYS_EXIT
)

var NONE = ArgType{TYPE_NONE, TYPE_NONE, 0}
var INT = ArgType{TYPE_INT, TYPE_NUM, uint32(unsafe.Sizeof(int(0)))}
var UINT = ArgType{TYPE_UINT, TYPE_NUM, uint32(unsafe.Sizeof(int(0)))}
var UINT32 = ArgType{TYPE_UINT32, TYPE_NUM, uint32(unsafe.Sizeof(uint(0)))}
var UINT64 = ArgType{TYPE_UINT64, TYPE_NUM, uint32(unsafe.Sizeof(uint64(0)))}
var STRING = ArgType{TYPE_STRING, TYPE_STRING, uint32(unsafe.Sizeof(uint64(0)))}
var STRING_ARR = ArgType{TYPE_STRING_ARR, TYPE_STRING_ARR, uint32(unsafe.Sizeof(uint64(0)))}
var POINTER = ArgType{TYPE_POINTER, TYPE_POINTER, uint32(unsafe.Sizeof(uint64(0)))}
var TIMESPEC = ArgType{TYPE_TIMESPEC, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Timespec{}))}
var STAT = ArgType{TYPE_STAT, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Stat_t{}))}
var STATFS = ArgType{TYPE_STATFS, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Statfs_t{}))}
var SIGACTION = ArgType{TYPE_SIGACTION, TYPE_STRUCT, uint32(unsafe.Sizeof(Sigaction{}))}
var UTSNAME = ArgType{TYPE_UTSNAME, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Utsname{}))}
var SOCKADDR = ArgType{TYPE_SOCKADDR, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.RawSockaddrAny{}))}
var RUSAGE = ArgType{TYPE_RUSAGE, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Rusage{}))}

// 64 位下这个是 unsigned long sig[_NSIG_WORDS]
// #define _NSIG       64
// #define _NSIG_BPW   __BITS_PER_LONG
// #define _NSIG_WORDS (_NSIG / _NSIG_BPW)
// unsigned long -> 4
var SIGSET = ArgType{TYPE_SIGSET, TYPE_STRUCT, 4 * 8}
var POLLFD = ArgType{TYPE_POLLFD, TYPE_STRUCT, uint32(unsafe.Sizeof(Pollfd{}))}

// 这是一种比较特殊的类型 即某个指针类型的参数 要在执行之后才有实际的值
// 但是最终要读取的大小/数量由另外一个参数决定 比如 pipe2的pipefd read的buf
var ARGASSIZE_BYTE = ArgType{TYPE_ARGASSIZE, TYPE_ARGASSIZE, 1}
var ARGASSIZE_INT = ArgType{TYPE_ARGASSIZE, TYPE_ARGASSIZE, 4}
var ARGASSIZE_UINT = ArgType{TYPE_ARGASSIZE, TYPE_ARGASSIZE, 4}
var ARGASSIZE_INT64 = ArgType{TYPE_ARGASSIZE, TYPE_ARGASSIZE, 8}
var ARGASSIZE_UINT64 = ArgType{TYPE_ARGASSIZE, TYPE_ARGASSIZE, 8}

func init() {
	// 结构体成员相关 某些参数的成员是指针类型的情况
	// Register(&PArgs{"sockaddr", []PArg{{"sockfd", INT}, {"addr", SOCKADDR}, {"addrlen", UINT32}}})

	// syscall相关
	Register(&SArgs{0, PA("io_setup", []PArg{A("nr_events", UINT), A("ctx_idp", POINTER)})})
	Register(&SArgs{8, PA("getxattr", []PArg{A("path", STRING), A("name", STRING), A("value", POINTER), A("size", INT)})})
	Register(&SArgs{9, PA("lgetxattr", []PArg{A("path", STRING), A("name", STRING), A("value", POINTER), A("size", INT)})})
	Register(&SArgs{10, PA("fgetxattr", []PArg{A("fd", INT), A("name", STRING), A("value", POINTER), A("size", INT)})})
	Register(&SArgs{17, PA("getcwd", []PArg{B("buf", STRING), A("size", UINT64)})})
	Register(&SArgs{22, PA("epoll_pwait", []PArg{A("epfd", INT), A("events", POINTER), A("maxevents", INT), A("timeout", INT)})})
	Register(&SArgs{23, PA("dup", []PArg{A("oldfd", INT)})})
	Register(&SArgs{24, PA("dup3", []PArg{A("oldfd", INT), A("newfd", UINT64), A("flags", INT)})})
	Register(&SArgs{29, PA("ioctl", []PArg{A("fd", INT), A("request", UINT64), A("arg0", INT), A("arg1", INT), A("arg2", INT), A("arg3", INT)})})
	Register(&SArgs{34, PA("mkdirat", []PArg{A("dirfd", INT), A("pathname", STRING), A("mode", INT)})})
	Register(&SArgs{35, PA("unlinkat", []PArg{A("dirfd", INT), A("pathname", STRING), A("flags", INT)})})
	Register(&SArgs{36, PA("symlinkat", []PArg{A("target", STRING), A("newdirfd", INT), A("linkpath", STRING)})})
	Register(&SArgs{37, PA("linkat", []PArg{A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING), A("flags", INT)})})
	Register(&SArgs{38, PA("renameat", []PArg{A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING)})})
	Register(&SArgs{39, PA("umount2", []PArg{A("target", STRING), A("flags", INT)})})
	Register(&SArgs{40, PA("mount", []PArg{A("source", INT), A("target", STRING), A("filesystemtype", STRING), A("mountflags", INT), A("data", POINTER)})})
	Register(&SArgs{43, PA("statfs", []PArg{A("path", STRING), B("buf", STATFS)})})
	Register(&SArgs{44, PA("fstatfs", []PArg{A("fd", INT), B("buf", STATFS)})})
	Register(&SArgs{45, PA("truncate", []PArg{A("path", STRING), A("length", INT)})})
	Register(&SArgs{46, PA("ftruncate", []PArg{A("fd", INT), A("length", INT)})})
	Register(&SArgs{47, PA("fallocate", []PArg{A("fd", INT), A("mode", INT), A("offset", INT), A("len", INT)})})
	Register(&SArgs{48, PA("faccessat", []PArg{A("dirfd", INT), A("pathname", STRING), A("flags", INT), A("mode", UINT32)})})
	Register(&SArgs{49, PA("chdir", []PArg{A("path", STRING)})})
	Register(&SArgs{50, PA("fchdir", []PArg{A("fd", INT)})})
	Register(&SArgs{51, PA("chroot", []PArg{A("path", STRING)})})
	Register(&SArgs{52, PA("fchmod", []PArg{A("fd", INT), A("mode", INT)})})
	Register(&SArgs{53, PA("fchmodat", []PArg{A("dirfd", INT), A("pathname", STRING), A("mode", INT), A("flags", INT)})})
	Register(&SArgs{54, PA("fchownat", []PArg{A("dirfd", INT), A("pathname", STRING), A("owner", INT), A("group", INT), A("flags", INT)})})
	Register(&SArgs{55, PA("fchown", []PArg{A("fd", INT), A("owner", INT), A("group", INT)})})
	Register(&SArgs{56, PA("openat", []PArg{A("dirfd", INT), A("pathname", STRING), A("flags", INT), A("mode", UINT32)})})
	Register(&SArgs{57, PA("close", []PArg{A("fd", INT)})})
	Register(&SArgs{58, PA("vhangup", []PArg{})})
	Register(&SArgs{59, PA("pipe2", []PArg{B("pipefd", POINTER), A("flags", INT)})})
	Register(&SArgs{60, PA("quotactl", []PArg{A("cmd", INT), A("special", STRING), A("id", INT), A("addr", INT)})})
	Register(&SArgs{61, PA("getdents64", []PArg{A("fd", INT), B("dirp", POINTER), A("count", INT)})})
	Register(&SArgs{63, PA("read", []PArg{A("fd", INT), B("buf", INT), A("count", INT)})})
	Register(&SArgs{64, PA("write", []PArg{A("fd", INT), A("buf", INT), A("count", INT)})})
	// 后续适配 指针+结构体 的情况
	Register(&SArgs{73, PA("ppoll", []PArg{A("fds", INT), A("nfds", INT), A("tmo_p", TIMESPEC), A("sigmask", INT)})})
	Register(&SArgs{78, PA("readlinkat", []PArg{A("dirfd", INT), A("pathname", STRING), B("buf", STRING), A("bufsiz", INT)})})
	Register(&SArgs{79, PA("newfstatat", []PArg{A("dirfd", INT), A("pathname", STRING), B("statbuf", STAT), A("flags", INT)})})
	Register(&SArgs{80, PA("fstat", []PArg{A("fd", INT), B("statbuf", STAT)})})
	Register(&SArgs{93, PArgs{"exit", B("ret", NONE), []PArg{A("status", INT)}}})
	Register(&SArgs{94, PArgs{"exit_group", B("ret", NONE), []PArg{A("status", INT)}}})
	Register(&SArgs{98, PA("futex", []PArg{A("uaddr", INT), A("futex_op", INT), A("val", INT), A("timeout", TIMESPEC)})})
	Register(&SArgs{101, PA("nanosleep", []PArg{A("req", TIMESPEC), A("rem", TIMESPEC)})})
	Register(&SArgs{117, PA("ptrace", []PArg{A("request", INT), A("pid", INT), A("addr", POINTER), A("data", POINTER)})})
	Register(&SArgs{129, PA("kill", []PArg{A("pid", INT), A("sig", INT)})})
	Register(&SArgs{130, PA("tkill", []PArg{A("tid", INT), A("sig", INT)})})
	Register(&SArgs{131, PA("tgkill", []PArg{A("tgid", INT), A("tid", INT), A("sig", INT)})})
	Register(&SArgs{133, PA("rt_sigsuspend", []PArg{A("mask", SIGSET)})})
	Register(&SArgs{134, PA("rt_sigaction", []PArg{A("signum", INT), A("act", SIGACTION), A("oldact", SIGACTION)})})
	Register(&SArgs{135, PA("rt_sigprocmask", []PArg{A("how", INT), A("set", UINT64), A("oldset", UINT64), A("sigsetsize", INT)})})
	Register(&SArgs{154, PA("setpgid", []PArg{A("pid", INT), A("pgid", INT)})})
	Register(&SArgs{155, PA("getpgid", []PArg{A("pid", INT)})})
	Register(&SArgs{160, PA("uname", []PArg{B("buf", UTSNAME)})})
	Register(&SArgs{165, PA("getrusage", []PArg{A("who", INT), B("usage", RUSAGE)})})
	Register(&SArgs{166, PA("umask", []PArg{A("mode", INT)})})
	Register(&SArgs{167, PA("prctl", []PArg{A("option", INT), A("arg2", UINT64), A("arg3", UINT64), A("arg4", UINT64), A("arg5", UINT64)})})
	Register(&SArgs{220, PA("clone", []PArg{A("fn", POINTER), A("stack", POINTER), A("flags", INT), A("arg0", INT), A("arg1", INT), A("arg2", INT)})})
	Register(&SArgs{221, PA("execve", []PArg{A("pathname", STRING), A("argv", STRING_ARR), A("envp", STRING_ARR)})})
	Register(&SArgs{260, PA("wait4", []PArg{A("pid", INT), A("wstatus", POINTER), A("options", INT), B("rusage", RUSAGE)})})
	Register(&SArgs{276, PA("renameat2", []PArg{A("olddirfd", INT), A("oldpath", STRING), A("newdirfd", INT), A("newpath", STRING), A("flags", INT)})})
	Register(&SArgs{277, PA("seccomp", []PArg{A("operation", INT), A("flags", INT), A("args", POINTER)})})
	Register(&SArgs{279, PA("memfd_create", []PArg{A("name", STRING), A("flags", INT)})})
	Register(&SArgs{280, PA("bpf", []PArg{A("cmd", INT), A("attr", POINTER), A("size", INT)})})
	Register(&SArgs{281, PA("execveat", []PArg{A("dirfd", INT), A("pathname", STRING), A("argv", STRING_ARR), A("envp", STRING_ARR), A("flags", INT)})})
	Register(&SArgs{203, PA("connect", []PArg{A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", UINT32)})})
	Register(&SArgs{439, PA("faccessat2", []PArg{A("dirfd", INT), A("pathname", STRING), A("flags", INT), A("mode", UINT32)})})
}
