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
}
type PArg = PointArg

func A(arg_name string, arg_type ArgType) PArg {
	return PArg{arg_name, SYS_ENTER, arg_type}
}

func B(arg_name string, arg_type ArgType) PArg {
	return PArg{arg_name, SYS_EXIT, arg_type}
}

type PointArgs struct {
	PointName string
	Args      []PointArg
}
type PArgs = PointArgs

type PointTypes struct {
	Count    uint32
	ArgTypes [MAX_POINT_ARG_COUNT]FilterArgType
}

type SysCallArgs struct {
	NR uint32
	PointArgs
}
type SArgs = SysCallArgs

func (this *PointArgs) Clone() IWatchPoint {
	args := new(PointArgs)
	args.PointName = this.PointName
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
	config := &PointTypes{
		Count:    uint32(len(this.Args)),
		ArgTypes: point_arg_types,
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

type IArgType interface {
	GetType() uint32
}

const (
	TYPE_NONE uint32 = iota
	TYPE_NUM
	TYPE_INT
	TYPE_UINT
	TYPE_UINT32
	TYPE_UINT64
	TYPE_STRING
	TYPE_POINTER
	TYPE_STRUCT
	TYPE_TIMESPEC
	TYPE_SOCKADDR
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
var POINTER = ArgType{TYPE_POINTER, TYPE_POINTER, uint32(unsafe.Sizeof(uint64(0)))}
var TIMESPEC = ArgType{TYPE_TIMESPEC, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.Timespec{}))}
var SOCKADDR = ArgType{TYPE_SOCKADDR, TYPE_STRUCT, uint32(unsafe.Sizeof(syscall.RawSockaddrAny{}))}

func init() {
	// syscall.Openat()
	// syscall.Uname()
	// syscall.Connect()
	// syscall.Nanosleep()

	// 结构体成员相关 某些参数的成员是指针类型的情况
	// Register(&PArgs{"sockaddr", []PArg{{"sockfd", INT}, {"addr", SOCKADDR}, {"addrlen", UINT32}}})

	// syscall相关
	Register(&SArgs{0, PArgs{"io_setup", []PArg{A("nr_events", UINT), A("ctx_idp", POINTER)}}})
	Register(&SArgs{17, PArgs{"getcwd", []PArg{B("buf", STRING), A("size", UINT64)}}})
	Register(&SArgs{56, PArgs{"openat", []PArg{A("dirfd", INT), A("pathname", STRING), A("flags", INT), A("mode", UINT32)}}})
	Register(&SArgs{101, PArgs{"nanosleep", []PArg{A("req", TIMESPEC), A("rem", TIMESPEC)}}})
	Register(&SArgs{203, PArgs{"connect", []PArg{A("sockfd", INT), A("addr", SOCKADDR), A("addrlen", UINT32)}}})
}
