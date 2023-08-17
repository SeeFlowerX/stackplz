package config

import (
	"encoding/json"
	"fmt"
)

// 结合其他项目构想一种新的方案 便于后续增补各类结构体的数据解析
// 而不是依赖配置文件去转换 某种程度上来说 硬编码反而是更好的选择

const MAX_POINT_ARG_COUNT = 10
const READ_INDEX_SKIP uint32 = 100
const READ_INDEX_REG uint32 = 101

const (
	FORBIDDEN uint32 = iota
	SYS_ENTER_EXIT
	SYS_ENTER
	SYS_EXIT
	UPROBE_ENTER_READ
)

type ArgType struct {
	ReadIndex      uint32
	AliasType      uint32
	Type           uint32
	Size           uint32
	ItemPerSize    uint32
	ItemCountIndex uint32
	ReadOffset     uint32
}

type IWatchPoint interface {
	Name() string
	Format() string
	Clone() IWatchPoint
}

type PointArgs struct {
	PointName string
	Ret       PointArg
	Args      []PointArg
}

type PArgs = PointArgs

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

type PArg = PointArg

func (this *ArgType) ToPointer() ArgType {
	// 通常定义的都是结构体 但是某些参数实际上传递的是这个结构体的指针
	// 那么这个时候把它转换为指针类型 在ebpf中再根据 AliasType 获取对应结构体大小的数据
	// 最终在用户态拿到数据具体再解析
	this.Type = TYPE_POINTER
	return *this
}

func (this *ArgType) SetIndex(index uint32) ArgType {
	this.ItemCountIndex = index
	return *this
}

func (this *ArgType) SetReadOffset(offset uint32) ArgType {
	this.ReadOffset = offset
	return *this
}

func (this *ArgType) SetItemPerSize(persize uint32) ArgType {
	this.ItemPerSize = persize
	return *this
}

func (this *PointArg) SetValue(value string) {
	this.ArgValue = value
}

func (this *PointArg) AppendValue(value string) {
	this.ArgValue += value
}

func AT(arg_alias_type, arg_type, read_count uint32) ArgType {
	return ArgType{READ_INDEX_REG, arg_alias_type, arg_type, read_count, 1, READ_INDEX_SKIP, 0}
}

func PA(nr string, args []PArg) PArgs {
	return PArgs{nr, B("ret", UINT64), args}
}

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

func NewWatchPoint(name string) IWatchPoint {
	point := &PointArgs{}
	point.PointName = name
	return point
}

func NewSysCallWatchPoint(name string) IWatchPoint {
	point := &SysCallArgs{}
	return point
}

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

var watchpoints = make(map[string]IWatchPoint)
var nrwatchpoints = make(map[uint32]IWatchPoint)
