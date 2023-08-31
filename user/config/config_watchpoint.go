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
const FILTER_INDEX_NONE uint32 = 0x1111
const FILTER_INDEX_SKIP uint32 = 0x1234

const (
	FORBIDDEN uint32 = iota
	SYS_ENTER_EXIT
	SYS_ENTER
	SYS_EXIT
	UPROBE_ENTER_READ
)

type ArgType struct {
	FilterIdx      uint32
	ReadIndex      uint32
	ReadOffset     uint32
	BaseType       uint32
	AliasType      uint32
	ReadCount      uint32
	ItemPerSize    uint32
	ItemCountIndex uint32
	tmp_index      uint32
}

type IWatchPoint interface {
	Name() string
	Format() string
	ParseType(int32) string
	ParseFlag(int32) string
	ParseProt(int32) string
	ParseMode(int32) string
	Clone() IWatchPoint
}

type PointArgs struct {
	PointName string
	Ret       PointArg
	Args      []PointArg
}

type PArgs = PointArgs

type FilterArgType struct {
	PointFlag uint32
	ArgType
}

type PointArg struct {
	ArgName   string
	PointFlag uint32
	ArgType
	ArgValue string
}

type PArg = PointArg

func (this *PointArg) SetValue(value string) {
	this.ArgValue = value
}

func (this *PointArg) AppendValue(value string) {
	this.ArgValue += value
}

func (this *PointArg) Format(p IWatchPoint, value uint64) string {
	switch this.ArgType {
	case UMODE_T:
		value_fixed := int32(uint16(value))
		this.ArgValue = fmt.Sprintf("%s=0x%x%s", this.ArgName, value_fixed, p.ParseMode(value_fixed))
		return this.ArgValue
	}
	switch this.AliasType {
	case TYPE_EXP_INT:
		value_fixed := int32(value)
		switch this.ArgName {
		case "flags":
			this.ArgValue = fmt.Sprintf("%s=0x%x%s", this.ArgName, value_fixed, p.ParseFlag(value_fixed))
		case "prot":
			this.ArgValue = fmt.Sprintf("%s=0x%x%s", this.ArgName, value_fixed, p.ParseProt(value_fixed))
		case "type":
			this.ArgValue = fmt.Sprintf("%s=0x%x%s", this.ArgName, value_fixed, p.ParseType(value_fixed))
		default:
			this.ArgValue = fmt.Sprintf("%s=%d", this.ArgName, value_fixed)
		}
	case TYPE_INT64:
		value_fixed := int64(value)
		if value_fixed <= 0 {
			this.ArgValue = fmt.Sprintf("%s=%d", this.ArgName, value_fixed)
		} else {
			this.ArgValue = fmt.Sprintf("%s=0x%x", this.ArgName, value_fixed)
		}
	case TYPE_UINT32:
		value_fixed := uint32(value)
		this.ArgValue = fmt.Sprintf("%s=0x%x", this.ArgName, value_fixed)
	default:
		this.ArgValue = fmt.Sprintf("%s=0x%x", this.ArgName, value)
	}
	return this.ArgValue
}

func (this *ArgType) SetBaseType(base_type uint32) {
	this.BaseType = base_type
}

func (this *ArgType) SetReadCount(read_count uint32) {
	this.ReadCount = read_count
}

func (this *ArgType) SetCountIndex(index uint32) {
	this.ItemCountIndex = index
}

func (this *ArgType) SetReadIndex(index uint32) {
	this.ReadIndex = index
}

func (this *ArgType) SetFilterIdx(index uint32) {
	this.FilterIdx = index
}

func (this *ArgType) SetReadOffset(offset uint32) {
	this.ReadOffset = offset
}

func (this *ArgType) SetItemPerSize(persize uint32) {
	this.ItemPerSize = persize
}

func (this *ArgType) ToPtr() ArgType {
	at := this.Clone()
	at.BaseType = TYPE_POINTER
	return at
}

func (this *ArgType) NewBaseType(base_type uint32) ArgType {
	at := this.Clone()
	at.BaseType = base_type
	return at
}

func (this *ArgType) NewReadCount(read_count uint32) ArgType {
	at := this.Clone()
	at.ReadCount = read_count
	return at
}

func (this *ArgType) NewCountIndex(index uint32) ArgType {
	at := this.Clone()
	at.ItemCountIndex = index
	return at
}

func (this *ArgType) NewReadIndex(index uint32) ArgType {
	at := this.Clone()
	at.ReadIndex = index
	return at
}

func (this *ArgType) NewReadOffset(offset uint32) ArgType {
	at := this.Clone()
	at.ReadOffset = offset
	return at
}

func (this *ArgType) NewItemPerSize(persize uint32) ArgType {
	at := this.Clone()
	at.ItemPerSize = persize
	return at
}

func (this *ArgType) String() string {
	var s string = ""
	s += fmt.Sprintf("read_index:%d, base_type:%d alias_type:%d ", this.ReadIndex, this.BaseType, this.AliasType)
	s += fmt.Sprintf("read_count:%d per:%d count_index:%d ", this.ReadCount, this.ItemPerSize, this.ItemCountIndex)
	s += fmt.Sprintf("off:%d", this.ReadOffset)
	return s
}

func (this *ArgType) Clone() ArgType {
	// 在涉及到类型变更的时候 记得先调用这个
	at := ArgType{}
	at.FilterIdx = this.FilterIdx
	at.ReadIndex = this.ReadIndex
	at.ReadOffset = this.ReadOffset
	at.BaseType = this.BaseType
	at.AliasType = this.AliasType
	at.ReadCount = this.ReadCount
	at.ItemPerSize = this.ItemPerSize
	at.ItemCountIndex = this.ItemCountIndex
	at.tmp_index = this.tmp_index
	return at
}

func AT(arg_alias_type, arg_base_type, read_count uint32) ArgType {
	return ArgType{FILTER_INDEX_NONE, READ_INDEX_REG, 0, arg_base_type, arg_alias_type, read_count, 1, READ_INDEX_SKIP, 0}
}

func PA(nr string, args []PArg) PArgs {
	return PArgs{nr, B("ret", UINT64), args}
}

func PAI(nr string, args []PArg) PArgs {
	return PArgs{nr, B("ret", EXP_INT), args}
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
func (this *PointArgs) ParseFlag(value int32) string {
	panic("PointArgs.ParseFlag() not implemented yet")
}
func (this *PointArgs) ParseProt(value int32) string {
	panic("PointArgs.ParseProt() not implemented yet")
}
func (this *PointArgs) ParseMode(value int32) string {
	panic("PointArgs.ParseMode() not implemented yet")
}
func (this *PointArgs) ParseType(value int32) string {
	panic("PointArgs.ParseType() not implemented yet")
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
