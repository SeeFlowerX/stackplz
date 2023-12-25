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

// type OpKeyConfig struct {
// 	OpList []*OpConfig
// }

// func NewOpKeyConfig() *OpKeyConfig {
// 	v := &OpKeyConfig{}
// 	return v
// }

// func (this *OpKeyConfig) AddOp(op *OpConfig) {
// 	this.OpList = append(this.OpList, op)
// }

// type ArgOpConfig struct {
// 	ArgName string
// 	ArgType *OpArgType
// }

// func (this *ArgOpConfig) IsPtr() bool {
// 	// 是否配置为指针类型
// 	return strings.HasPrefix(this.ArgName, "*")
// }

// type PointArgsConfig struct {
// 	Nr           uint32
// 	Name         string
// 	Args         []*ArgOpConfig
// 	ArgsSysExit  *OpKeyConfig
// 	ArgsSysEnter *OpKeyConfig
// }

// func (this *PointArgsConfig) GetConfig() PointConfig_C {
// 	point := PointConfig_C{}
// 	point.OpCount = uint32(len(this.ArgsSysEnter.OpList))
// 	if int(point.OpCount) > len(point.OpIndexList) {
// 		panic(fmt.Sprintf("too many op for %s", this.Name))
// 	}
// 	for i, op := range this.ArgsSysEnter.OpList {
// 		point.OpIndexList[i] = op.Index
// 	}
// 	// fmt.Println("[GetConfig]", this.Name, point)
// 	return point
// }

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

// func (this *SyscallPoints) GetPointConfigByNR(nr uint32) *OpKeyConfig {
// 	for _, point := range this.points {
// 		if point.Nr == nr {
// 			return point.ArgsSysEnter
// 		}
// 	}
// 	panic(fmt.Sprintf("GetPointConfigByNR failed for nr %d", nr))
// }

// func (this *SyscallPoints) GetPointConfigByName(name string) *OpKeyConfig {
// 	for _, point := range this.points {
// 		if point.Name == name {
// 			return point.ArgsSysEnter
// 		}
// 	}
// 	panic(fmt.Sprintf("GetPointConfigByName failed for name %s", name))
// }

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

const (
	OP_LIST_COMMON_START uint32 = 0x400
)

type OpKeyHelper struct {
	op_list              map[uint32]OpConfig
	reg_index_op_key_map map[int]uint32
}

func (this *OpKeyHelper) get_op_config(op_key uint32) OpConfig {
	for k, v := range this.op_list {
		if k == op_key {
			return v
		}
	}
	panic(fmt.Sprintf("get_op_config for key:%d not exists", op_key))
}

func (this *OpKeyHelper) get_default_op_key(op_code uint32) uint32 {
	for k, v := range this.op_list {
		if v.Code == op_code && v.Value == 0 {
			return k
		}
	}
	panic(fmt.Sprintf("default_op_key for code:%d not exists", op_code))
}

func (this *OpKeyHelper) get_op_key(opc OpConfig) uint32 {
	for k, v := range this.op_list {
		if v.Code == opc.Code && v.Value == opc.Value {
			return k
		}
	}
	next_op_key := OP_LIST_COMMON_START + uint32(len(this.op_list))
	this.op_list[next_op_key] = opc
	return next_op_key
}

func (this *OpKeyHelper) add_reg_index_op_config(reg_index int, op_key uint32) {
	this.reg_index_op_key_map[reg_index] = op_key
}

func (this *OpKeyHelper) get_reg_index_op_key(reg_index int) uint32 {
	return this.reg_index_op_key_map[reg_index]
}

func (this *OpKeyHelper) GetOpList() map[uint32]OpConfig {
	// 取出会被用到的 op
	// 根据 op_key 去重即可
	return this.op_list
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
		a_p.BuildOpList(point_arg.PointType == EBPF_SYS_ENTER)
		a_point_args = append(a_point_args, a_p)
		b_p := point_arg.Clone()
		b_p.SetRegIndex(uint32(reg_index))
		b_p.BuildOpList(point_arg.PointType == EBPF_SYS_EXIT)
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

func init() {

	var PTR = GetArgType("ptr")
	var INT = GetArgType("int")
	// var UINT = GetArgType("uint")
	// var INT8 = GetArgType("int8")
	var INT16 = GetArgType("int16")
	// var INT32 = GetArgType("int32")
	// var INT64 = GetArgType("int64")
	// var UINT8 = GetArgType("uint8")
	// var UINT16 = GetArgType("uint16")
	// var UINT32 = GetArgType("uint32")
	// var UINT64 = GetArgType("uint64")
	// var POINTER = GetArgType("pointer")
	var STRING = GetArgType("string")
	var BUFFER = GetArgType("buffer")
	// var STRUCT = GetArgType("struct")
	var IOVEC = GetArgType("iovec")
	var MSGHDR = GetArgType("msghdr")
	var SOCKLEN_T = GetArgType("socklen_t")
	var SIZE_T = GetArgType("size_t")
	// var SSIZE_T = GetArgType("ssize_t")
	var SOCKADDR = GetArgType("sockaddr")
	// var TIMESPEC = GetArgType("timespec")
	// // 对一些复杂结构体的读取配置进行补充

	// // 以指定寄存器作为数据读取长度
	// AT_BUFFER_X2 := BuildBufferRegIndex(REG_ARM64_X2)

	// // 以指定寄存器作为数据读取次数
	// AT_IOVEC_X2 := BuildIovecRegIndex(REG_ARM64_X2)

	// R(56, "openat", X("dirfd", AT_INT), X("pathname", AT_STRING), X("flags", AT_INT), X("mode", AT_INT16))
	// R(66, "writev", X("fd", AT_INT), X("*iov", AT_IOVEC_X2), X("iovcnt", AT_INT))
	// // 需要修正 syscall执行后读取
	// R(78, "readlinkat", X("dirfd", AT_INT), X("pathname", AT_STRING), Y("buf", AT_STRING), X("bufsiz", AT_INT))
	// R(79, "newfstatat", X("dirfd", AT_INT), X("pathname", AT_STRING), Y("statbuf", AT_STAT), X("flags", AT_INT))

	// R(129, "kill", X("pid", AT_INT), X("sig", AT_INT))
	// R(130, "tkill", X("tid", AT_INT), X("sig", AT_INT))
	// R(131, "tgkill", X("tgid", AT_INT), X("tid", AT_INT), X("sig", AT_INT))
	// R(132, "sigaltstack", X("ss", AT_STACK), X("old_ss", AT_STACK))
	// R(133, "rt_sigsuspend", X("mask", AT_SIGSET))
	// R(134, "rt_sigaction", X("signum", AT_INT), X("act", AT_SIGACTION), X("oldact", AT_SIGACTION))
	// R(135, "rt_sigprocmask", X("how", AT_INT), X("set", AT_UINT64), X("oldset", AT_UINT64), X("sigsetsize", AT_INT))
	// R(136, "rt_sigpending", X("uset", AT_SIGSET), X("sigsetsize", AT_INT))
	// R(137, "rt_sigtimedwait", X("uthese", AT_SIGSET), X("uinfo", AT_SIGINFO), X("uts", AT_TIMESPEC), X("sigsetsize", AT_INT))
	// R(138, "rt_sigqueueinfo", X("pid", AT_INT), X("sig", AT_INT), X("uinfo", AT_SIGINFO))
	// R(139, "rt_sigreturn", X("mask", AT_INT))

	// R(203, "connect", X("sockfd", AT_INT), X("addr", AT_SOCKADDR), X("addrlen", AT_INT))
	// R(206, "sendto", X("sockfd", AT_INT), X("*buf", AT_BUFFER_X2), X("len", AT_INT), X("flags", AT_INT), X("addr", AT_SOCKADDR), X("addrlen", AT_INT))
	// R(211, "sendmsg", X("sockfd", AT_INT), X("*msg", AT_MSGHDR), X("flags", AT_INT))

	// R(240, "rt_tgsigqueueinfo", X("tgid", AT_INT), X("tid", AT_INT), X("sig", AT_INT), X("siginfo", AT_SIGINFO))

	// BUFFER_256 := ValueAsBufferReadLen(BUFFER, 256)
	BUFFER_X2 := RegAsBufferReadLen(BUFFER, REG_ARM64_X2)
	IOVEC_X2 := RegAsIovecLoopCount(IOVEC, REG_ARM64_X2)

	INT_SOCKET_FLAGS := AttachFlagsParser(INT, SocketFlagsParser)
	INT_FILE_FLAGS := AttachFlagsParser(INT, FileFlagsParser)
	INT16_PERM_FLAGS := AttachFlagsParser(INT16, PermissionFlagsParser)

	// MSGHDR.DumpOpList()

	R(56, "openat", A("dirfd", INT), A("*pathname", STRING), A("flags", INT_FILE_FLAGS), A("mode", INT16_PERM_FLAGS))
	R(66, "writev", A("fd", INT), A("*iov", IOVEC_X2), A("iovcnt", INT))
	R(198, "socket", A("domain", INT), A("type", INT_SOCKET_FLAGS), A("protocol", INT))
	// R(199, "socketpair", A("domain", INT), A("type", INT), A("protocol", INT), B("sv", SOCKET_SV))
	R(200, "bind", A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(201, "listen", A("sockfd", INT), A("backlog", INT))
	R(202, "accept", A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(203, "connect", A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(204, "getsockname", A("sockfd", INT), B("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(205, "getpeername", A("sockfd", INT), B("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(206, "sendto", A("sockfd", INT), A("*buf", BUFFER_X2), A("len", SIZE_T), A("flags", INT), A("addr", SOCKADDR), A("addrlen", SOCKLEN_T))
	R(207, "recvfrom", A("sockfd", INT), B("*buf", BUFFER_X2), A("len", SIZE_T), A("flags", INT))
	R(208, "setsockopt", A("sockfd", INT), A("level", INT), A("optname", INT), A("optval", PTR), A("optlen", SOCKLEN_T))
	R(209, "getsockopt", A("sockfd", INT), A("level", INT), A("optname", INT), B("optval", PTR), A("optlen", PTR))
	R(210, "shutdown", A("sockfd", INT), A("how", INT))
	R(211, "sendmsg", A("sockfd", INT), A("*msg", MSGHDR), A("flags", INT))

}