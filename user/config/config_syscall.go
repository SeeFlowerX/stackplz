package config

import (
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"
)

// 结合其他项目构想一种新的方案 便于后续增补各类结构体的数据解析
// 而不是依赖配置文件去转换 某种程度上来说 硬编码反而是更好的选择

type ArgType struct {
	Type    uint32      `json:"Type"`
	Size    interface{} `json:"Size"`
	SubType uint32      `json:"SubType"`
}

type Arg struct {
	ArgName string `json:"Name"`
	ArgType
}

type Args struct {
	PointName string
	Args      []Arg
}

type SysCallArgs struct {
	Args
	NR uint32
}

func (this *Args) Clone() IWatchPoint {
	args := new(Args)
	args.PointName = this.PointName
	args.Args = this.Args
	return args
}

// func (this *Args) AddArg(name string, arg_type, size, subtype uint32) IWatchPoint {
// 	arg := &Arg{name, arg_type, size, subtype}
// 	this.Args = append(this.Args, *arg)
// 	return this
// }

func (this *Args) Format() string {
	args, err := json.Marshal(this.Args)
	if err != nil {
		panic(fmt.Sprintf("Args Format err:%v", err))
	}
	return fmt.Sprintf("[%s] %d %s", this.PointName, len(this.Args), args)
}

func (this *Args) Name() string {
	return this.PointName
}

type IWatchPoint interface {
	Name() string
	Format() string
	Clone() IWatchPoint
}

func NewWatchPoint(name string) IWatchPoint {
	point := &Args{}
	point.PointName = name
	return point
}

func NewSysCallWatchPoint(name string) IWatchPoint {
	point := &SysCallArgs{}
	return point
}

var watchpoints = make(map[string]IWatchPoint)

func Register(p IWatchPoint) {
	if p == nil {
		panic("Register watchpoint is nil")
	}
	name := p.Name()
	if _, dup := watchpoints[name]; dup {
		panic(fmt.Sprintf("Register called twice for watchpoint %s", name))
	}
	watchpoints[name] = p
}

func GetAllWatchPoints() map[string]IWatchPoint {
	return watchpoints
}

func GetWatchPointByName(pointName string) IWatchPoint {
	m, f := watchpoints[pointName]
	if f {
		return m.Clone()
	}
	return nil
}

type IArgType interface {
	GetType() uint32
}

const (
	TYPE_NONE uint32 = iota
	TYPE_INT
	TYPE_UINT32
	TYPE_STRING
	TYPE_POINTER
	TYPE_STRUCT
	TYPE_TIMESPEC
)

var ARG_TYPE_NONE = ArgType{TYPE_NONE, 0, TYPE_NONE}
var ARG_TYPE_INT = ArgType{TYPE_INT, unsafe.Sizeof(int(0)), TYPE_NONE}
var ARG_TYPE_UINT32 = ArgType{TYPE_UINT32, unsafe.Sizeof(uint32(0)), TYPE_NONE}
var ARG_TYPE_STRING = ArgType{TYPE_STRING, unsafe.Sizeof(uint64(0)), TYPE_NONE}
var ARG_TYPE_POINTER = ArgType{TYPE_POINTER, unsafe.Sizeof(uint64(0)), TYPE_NONE}
var ARG_TYPE_TIMESPEC = ArgType{TYPE_TIMESPEC, unsafe.Sizeof(syscall.Timespec{}), TYPE_STRUCT}

func init() {
	// syscall.Openat()
	// syscall.Nanosleep()
	Register(&Args{"openat", []Arg{{"dirfd", ARG_TYPE_INT}, {"pathname", ARG_TYPE_STRING}, {"flags", ARG_TYPE_INT}, {"mode", ARG_TYPE_UINT32}}})
	Register(&Args{"nanosleep", []Arg{{"req", ARG_TYPE_TIMESPEC}, {"rem", ARG_TYPE_TIMESPEC}}})
}
